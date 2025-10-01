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

        // ✅ Find user by email (not username)
        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        // ✅ Generate JWT with email instead of username
        $token = $jwtService->generateToken([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
        ]);

        return new JsonResponse(['token' => $token]);
    }

    // 🔹 Add this test route below
    #[Route('/api/test-jwt', name: 'api_test_jwt', methods: ['GET'])]
    public function testJwt(JwtService $jwtService): JsonResponse
    {
        return new JsonResponse([
            'class' => get_class($jwtService),
            'ok' => true
        ]);
    }
}
