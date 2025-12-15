<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\JwtService;
use App\Service\ActivityLogService;
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
        JwtService $jwtService,
        ActivityLogService $activityLogService
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        // Log the login activity
        $activityLogService->logLogin($user, $request);

        $token = $jwtService->generateToken([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
            'roles' => $user->getRoles()
        ]);

        return new JsonResponse([
            'token' => $token,
            'roles' => $user->getRoles()
        ]);
    }

    #[Route('/api/logout', name: 'api_logout', methods: ['POST'])]
    public function logout(
        Request $request,
        JwtService $jwtService,
        EntityManagerInterface $em,
        ActivityLogService $activityLogService
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
                    // Only log logout activity for admin and staff roles (not regular users)
                    $userRoles = $user->getRoles();
                    $isAdminOrStaff = in_array('ROLE_ADMIN', $userRoles) || in_array('ROLE_STAFF', $userRoles);
                    
                    if ($isAdminOrStaff) {
                        // Log the logout activity in activity logs for admin and staff
                        $activityLogService->logLogout($user, $request);
                    }
                    // Note: Regular users (ROLE_USER only) can logout but it won't be logged
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