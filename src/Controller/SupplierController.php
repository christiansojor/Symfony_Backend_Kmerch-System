<?php

namespace App\Controller;

use App\Entity\ActivityLog;
use App\Entity\Supplier;
use App\Entity\User;
use App\Repository\SupplierRepository;
use App\Service\JwtService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Psr\Log\LoggerInterface;

#[Route('/api/suppliers')]
final class SupplierController extends AbstractController
{
    public function __construct(
        private JwtService $jwtService,
        private Security $security,
        private LoggerInterface $logger
    ) {}

    private function getUserFromToken(Request $request, EntityManagerInterface $em): ?User
    {
        $authHeader = $request->headers->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = $this->jwtService->validateToken($token);
            $userId = $decoded['id'] ?? null;

            if (!$userId) {
                return null;
            }

            return $em->getRepository(User::class)->find($userId);
        } catch (\Exception $e) {
            $this->logger->error('Failed to get user from token', ['error' => $e->getMessage()]);
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

            // Direct logging as backup - must happen after flush to get supplier ID
            $this->logActivity('CREATE', $supplier, $request, $em, true);

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

            $errors = $validator->validate($supplier);
            if (count($errors) > 0) {
                $errorMessages = [];
                foreach ($errors as $error) {
                    $errorMessages[$error->getPropertyPath()] = $error->getMessage();
                }
                return $this->json($errorMessages, 400);
            }

            $em->flush();

            // Direct logging as backup
            $this->logActivity('UPDATE', $supplier, $request, $em, true);

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

            // Capture data before deletion
            $supplierData = [
                'id' => $supplier->getId(),
                'companyName' => $supplier->getCompanyName(),
                'email' => $supplier->getEmail(),
                'status' => $supplier->getStatus()
            ];

            $em->remove($supplier);
            $em->flush();

            // Direct logging as backup
            $this->logActivity('DELETE', null, $request, $em, true, $supplierData);

            return $this->json(['message' => 'Supplier deleted successfully']);
        } catch (\Exception $e) {
            return $this->json(['error' => 'Failed to delete supplier: ' . $e->getMessage()], 500);
        }
    }

    private function logActivity(string $action, ?Supplier $supplier, Request $request, EntityManagerInterface $em, bool $useNewConnection = false, ?array $supplierData = null): void
    {
        try {
            // Get user from JWT token directly instead of Security component
            $user = $this->getUserFromToken($request, $em);
            
            $this->logger->info('SupplierController: Direct logging attempt', [
                'action' => $action,
                'has_user' => $user !== null,
                'user_class' => $user ? get_class($user) : null,
                'user_id' => $user ? $user->getId() : null,
                'username' => $user ? $user->getUsername() : null
            ]);

            if (!$user || !$user instanceof User) {
                $this->logger->warning('SupplierController: No valid user for logging');
                return;
            }

            $roles = $user->getRoles();
            if (!in_array('ROLE_ADMIN', $roles) && !in_array('ROLE_STAFF', $roles)) {
                return;
            }

            $targetData = ['entity' => 'Supplier'];
            
            if ($supplier) {
                $targetData['entity_id'] = $supplier->getId();
                $targetData['entity_name'] = $supplier->getCompanyName();
                $targetData['email'] = $supplier->getEmail();
                $targetData['status'] = $supplier->getStatus();
            } elseif ($supplierData) {
                // For deleted suppliers
                $targetData = array_merge($targetData, [
                    'entity_id' => $supplierData['id'],
                    'entity_name' => $supplierData['companyName'],
                    'email' => $supplierData['email'],
                    'status' => $supplierData['status']
                ]);
            }

            $activityLog = new ActivityLog();
            $activityLog->setUserId($user->getId());
            $activityLog->setUsername($user->getUsername());
            $activityLog->setRole(implode(',', $user->getRoles()));
            $activityLog->setAction($action);
            $activityLog->setTargetData(json_encode($targetData));

            // Use a fresh entity manager if needed to avoid disconnection issues
            if ($useNewConnection) {
                // Get a fresh entity manager
                $freshEm = $this->container->get('doctrine')->getManager();
                $freshEm->persist($activityLog);
                $freshEm->flush();
                $this->logger->info('SupplierController: Activity logged with fresh EM', [
                    'action' => $action,
                    'username' => $user->getUsername()
                ]);
            } else {
                $em->persist($activityLog);
                $em->flush();
                $this->logger->info('SupplierController: Activity logged successfully', [
                    'action' => $action,
                    'username' => $user->getUsername()
                ]);
            }

        } catch (\Exception $e) {
            $this->logger->error('SupplierController: Failed to log activity', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }
}