<?php

namespace App\Controller;

use App\Entity\Supplier;
use App\Entity\User;
use App\Repository\SupplierRepository;
use App\Service\ActivityLogService;
use App\Service\JwtService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;

#[Route('/api/suppliers')]
final class SupplierController extends AbstractController
{
    public function __construct(
        private ActivityLogService $activityLogService,
        private JwtService $jwtService
    ) {}

    /**
     * Get current user from JWT token (admin/staff only for logging)
     */
    private function getCurrentUser(Request $request, EntityManagerInterface $em): ?User
    {
        $authHeader = $request->headers->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = $this->jwtService->validateToken($token);
            
            if ($decoded === null || !is_array($decoded)) {
                return null;
            }
            
            $userId = $decoded['id'] ?? null;

            if (!$userId) {
                return null;
            }

            $user = $em->getRepository(User::class)->find($userId);

            if (!$user) {
                return null;
            }

            // Only log for admin/staff
            $roles = $user->getRoles();
            if (!in_array('ROLE_ADMIN', $roles) && !in_array('ROLE_STAFF', $roles)) {
                return null;
            }

            return $user;
        } catch (\Exception $e) {
            return null;
        }
    }
    #[Route('', name: 'api_supplier_index', methods: ['GET'])]
    public function index(SupplierRepository $supplierRepository): JsonResponse
    {
        try {
            $suppliers = $supplierRepository->findAll();
            $data = array_map(fn(Supplier $s) => [
                'id' => $s->getId(),
                'companyName' => $s->getCompanyName(),
                'company_name' => $s->getCompanyName(),
                'name' => $s->getCompanyName(),
                'contactPerson' => $s->getContactPerson(),
                'email' => $s->getEmail(),
                'phone' => $s->getPhone(),
                'address' => $s->getAddress(),
                'status' => $s->getStatus(),
            ], $suppliers);

            return $this->json($data);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to fetch suppliers: ' . $e->getMessage()], 500);
        }
    }

    #[Route('', name: 'api_supplier_new', methods: ['POST'])]
    public function new(Request $request, EntityManagerInterface $em, ValidatorInterface $validator): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);
            if (!$data) {
                return $this->json(['error' => 'Invalid JSON data'], 400);
            }

            if (empty($data['companyName'])) {
                return $this->json(['error' => 'Company name is required'], 400);
            }

            $supplier = (new Supplier())
                ->setCompanyName($data['companyName'])
                ->setContactPerson($data['contactPerson'] ?? null)
                ->setEmail($data['email'] ?? null)
                ->setPhone($data['phone'] ?? null)
                ->setAddress($data['address'] ?? null)
                ->setStatus($data['status'] ?? 'active');

            // ✅ Validate entity fields before saving
            $errors = $validator->validate($supplier);
            if (count($errors) > 0) {
                $errorMessages = [];
                foreach ($errors as $error) {
                    $errorMessages[$error->getPropertyPath()] = $error->getMessage();
                }
                return $this->json($errorMessages, 400);
            }

            $em->persist($supplier);
            $em->flush();

            // Log activity for admin/staff
            $currentUser = $this->getCurrentUser($request, $em);
            if ($currentUser) {
                $this->activityLogService->logCreate(
                    $currentUser,
                    'Supplier',
                    $supplier->getId(),
                    $supplier->getCompanyName(),
                    $request
                );
            }

            return $this->json([
                'message' => 'Supplier created successfully',
                'id' => $supplier->getId(),
            ], 201);

        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to create supplier: ' . $e->getMessage()], 500);
        }
    }

    #[Route('/{id}', name: 'api_supplier_show', methods: ['GET'])]
    public function show(int $id, SupplierRepository $repo): JsonResponse
    {
        try {
            $supplier = $repo->find($id);
            if (!$supplier) {
                return $this->json(['error' => 'Supplier not found'], 404);
            }

            return $this->json([
                'id' => $supplier->getId(),
                'companyName' => $supplier->getCompanyName(),
                'company_name' => $supplier->getCompanyName(),
                'name' => $supplier->getCompanyName(),
                'contactPerson' => $supplier->getContactPerson(),
                'email' => $supplier->getEmail(),
                'phone' => $supplier->getPhone(),
                'address' => $supplier->getAddress(),
                'status' => $supplier->getStatus(),
            ]);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to fetch supplier: ' . $e->getMessage()], 500);
        }
    }

    #[Route('/{id}', name: 'api_supplier_edit', methods: ['PUT'])]
    public function edit(int $id, Request $request, EntityManagerInterface $em, SupplierRepository $repo, ValidatorInterface $validator): JsonResponse
    {
        try {
            $supplier = $repo->find($id);
            if (!$supplier) {
                return $this->json(['error' => 'Supplier not found'], 404);
            }

            $data = json_decode($request->getContent(), true);
            if (!$data) {
                return $this->json(['error' => 'Invalid JSON data'], 400);
            }

            $supplier
                ->setCompanyName($data['companyName'] ?? $supplier->getCompanyName())
                ->setContactPerson($data['contactPerson'] ?? $supplier->getContactPerson())
                ->setEmail($data['email'] ?? $supplier->getEmail())
                ->setPhone($data['phone'] ?? $supplier->getPhone())
                ->setAddress($data['address'] ?? $supplier->getAddress())
                ->setStatus($data['status'] ?? $supplier->getStatus());

            // ✅ Validate updates too
            $errors = $validator->validate($supplier);
            if (count($errors) > 0) {
                $errorMessages = [];
                foreach ($errors as $error) {
                    $errorMessages[$error->getPropertyPath()] = $error->getMessage();
                }
                return $this->json($errorMessages, 400);
            }

            $em->flush();

            // Log activity for admin/staff
            $currentUser = $this->getCurrentUser($request, $em);
            if ($currentUser) {
                $this->activityLogService->logUpdate(
                    $currentUser,
                    'Supplier',
                    $supplier->getId(),
                    $supplier->getCompanyName(),
                    $request
                );
            }

            return $this->json(['message' => 'Supplier updated successfully']);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to update supplier: ' . $e->getMessage()], 500);
        }
    }

    #[Route('/{id}', name: 'api_supplier_delete', methods: ['DELETE'])]
    public function delete(int $id, Request $request, EntityManagerInterface $em, SupplierRepository $repo): JsonResponse
    {
        try {
            $supplier = $repo->find($id);
            if (!$supplier) {
                return $this->json(['error' => 'Supplier not found'], 404);
            }

            // Store info before deletion for logging
            $supplierId = $supplier->getId();
            $supplierName = $supplier->getCompanyName();

            $em->remove($supplier);
            $em->flush();

            // Log activity for admin/staff
            $currentUser = $this->getCurrentUser($request, $em);
            if ($currentUser) {
                $this->activityLogService->logDelete(
                    $currentUser,
                    'Supplier',
                    $supplierId,
                    $supplierName,
                    $request
                );
            }

            return $this->json(['message' => 'Supplier deleted successfully']);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to delete supplier: ' . $e->getMessage()], 500);
        }
    }
}
