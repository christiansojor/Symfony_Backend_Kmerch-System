<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

class AuthController extends AbstractController
{
    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(
        Request $request,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $passwordHasher,
        JwtService $jwtService
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        // Check if account is disabled or archived
        if ($user->getStatus() !== 'active') {
            $statusMessage = $user->getStatus() === 'disabled' 
                ? 'Your account has been disabled. Please contact an administrator.'
                : 'Your account has been archived. Please contact an administrator.';
            return new JsonResponse(['error' => $statusMessage], 403);
        }

        // Log the login activity for admin and staff only
        $roles = $user->getRoles();
        if (in_array('ROLE_ADMIN', $roles) || in_array('ROLE_STAFF', $roles)) {
            try {
                $targetData = [
                    'entity' => 'User',
                    'entity_id' => $user->getId(),
                    'entity_name' => $user->getUsername(),
                ];

                $activityLog = new \App\Entity\ActivityLog();
                $activityLog->setUserId($user->getId());
                $activityLog->setUsername($user->getUsername());
                $activityLog->setRole(implode(',', $user->getRoles()));
                $activityLog->setAction('LOGIN');
                $activityLog->setTargetData(json_encode($targetData));

                $em->persist($activityLog);
                $em->flush();
            } catch (\Exception $e) {
                // Log error but don't fail login
            }
        }

        $token = $jwtService->generateToken([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles()
        ]);

        return new JsonResponse([
            'token' => $token,
            'roles' => $user->getRoles(),
            'user' => [
                'id' => $user->getId(),
                'username' => $user->getUsername(),
                'email' => $user->getEmail(),
                'firstName' => $user->getFirstName(),
                'lastName' => $user->getLastName(),
                'role' => $user->getRoles()[0] ?? 'ROLE_USER'
            ]
        ]);
    }

    #[Route('/api/logout', name: 'api_logout', methods: ['POST'])]
    public function logout(
        Request $request,
        JwtService $jwtService,
        EntityManagerInterface $em
    ): JsonResponse {
        $authHeader = $request->headers->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return new JsonResponse(['error' => 'No token provided'], 401);
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = $jwtService->validateToken($token);
            $userId = $decoded['id'] ?? null;

            if ($userId) {
                $user = $em->getRepository(User::class)->find($userId);
                
                if ($user) {
                    // Only log logout activity for admin and staff roles
                    $roles = $user->getRoles();
                    if (in_array('ROLE_ADMIN', $roles) || in_array('ROLE_STAFF', $roles)) {
                        try {
                            $targetData = [
                                'entity' => 'User',
                                'entity_id' => $user->getId(),
                                'entity_name' => $user->getUsername(),
                            ];

                            $activityLog = new \App\Entity\ActivityLog();
                            $activityLog->setUserId($user->getId());
                            $activityLog->setUsername($user->getUsername());
                            $activityLog->setRole(implode(',', $user->getRoles()));
                            $activityLog->setAction('LOGOUT');
                            $activityLog->setTargetData(json_encode($targetData));

                            $em->persist($activityLog);
                            $em->flush();
                        } catch (\Exception $e) {
                            // Log error but don't fail logout
                        }
                    }
                }
            }

            return new JsonResponse(['message' => 'Logged out successfully']);

        } catch (\Exception $e) {
            return new JsonResponse(['error' => 'Invalid token'], 401);
        }
    }

    #[Route('/api/test-jwt', name: 'api_test_jwt', methods: ['GET'])]
    public function testJwt(JwtService $jwtService): JsonResponse
    {
        return new JsonResponse([
            'class' => get_class($jwtService),
            'ok' => true
        ]);
    }
}