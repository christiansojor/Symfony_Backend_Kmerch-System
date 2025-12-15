<?php

namespace App\Controller;

use App\Entity\ActivityLog;
use App\Service\JwtService;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class ActivityLogController extends AbstractController
{
    private function validateAdminToken(Request $request, JwtService $jwtService, EntityManagerInterface $em): ?array
    {
        $authHeader = $request->headers->get('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return ['error' => 'No token provided', 'code' => 401];
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = $jwtService->validateToken($token);
            $userId = $decoded['id'] ?? null;

            if (!$userId) {
                return ['error' => 'Invalid token structure', 'code' => 401];
            }

            $user = $em->getRepository(User::class)->find($userId);

            if (!$user) {
                return ['error' => 'User not found', 'code' => 401];
            }

            if (!in_array('ROLE_ADMIN', $user->getRoles())) {
                return ['error' => 'Access denied. Admin only.', 'code' => 403];
            }

            return ['user' => $user];

        } catch (\Exception $e) {
            return ['error' => 'Invalid or expired token', 'code' => 401];
        }
    }

    #[Route('/api/admin/activity-logs', name: 'api_admin_get_activity_logs', methods: ['GET'])]
    public function getActivityLogs(
        Request $request,
        JwtService $jwtService,
        EntityManagerInterface $em
    ): JsonResponse {
        $validation = $this->validateAdminToken($request, $jwtService, $em);
        
        if (isset($validation['error'])) {
            return $this->json(['error' => $validation['error']], $validation['code']);
        }

        // Get query parameters for filtering
        $username = $request->query->get('username');
        $action = $request->query->get('action');
        $startDate = $request->query->get('startDate');
        $endDate = $request->query->get('endDate');
        $limit = (int) $request->query->get('limit', 100);
        $offset = (int) $request->query->get('offset', 0);

        // Build query using QueryBuilder directly
        $qb = $em->createQueryBuilder();
        $qb->select('a')
           ->from(ActivityLog::class, 'a');

        // Apply filters
        if ($username) {
            $qb->andWhere('a.username LIKE :username')
               ->setParameter('username', '%' . $username . '%');
        }

        if ($action) {
            $qb->andWhere('a.action = :action')
               ->setParameter('action', $action);
        }

        if ($startDate) {
            $startDateTime = new \DateTime($startDate);
            $qb->andWhere('a.createdAt >= :startDate')
               ->setParameter('startDate', $startDateTime);
        }

        if ($endDate) {
            $endDateTime = new \DateTime($endDate . ' 23:59:59');
            $qb->andWhere('a.createdAt <= :endDate')
               ->setParameter('endDate', $endDateTime);
        }

        // Get total count before pagination
        $countQb = clone $qb;
        $countQb->select('COUNT(a.id)');
        $total = (int) $countQb->getQuery()->getSingleScalarResult();

        // Apply pagination and ordering
        $qb->orderBy('a.createdAt', 'DESC')
           ->setMaxResults($limit)
           ->setFirstResult($offset);

        $logs = $qb->getQuery()->getResult();

        $logsData = array_map(function($log) {
            return [
                'id' => $log->getId(),
                'userId' => $log->getUserId(),
                'username' => $log->getUsername(),
                'role' => $log->getRole(),
                'action' => $log->getAction(),
                'targetData' => $log->getTargetData(),
                'createdAt' => $log->getCreatedAt()->format('Y-m-d H:i:s'),
            ];
        }, $logs);

        return $this->json([
            'logs' => $logsData,
            'total' => $total,
            'limit' => $limit,
            'offset' => $offset
        ]);
    }

    #[Route('/api/admin/activity-logs/actions', name: 'api_admin_get_activity_actions', methods: ['GET'])]
    public function getAvailableActions(
        Request $request,
        JwtService $jwtService,
        EntityManagerInterface $em
    ): JsonResponse {
        $validation = $this->validateAdminToken($request, $jwtService, $em);
        
        if (isset($validation['error'])) {
            return $this->json(['error' => $validation['error']], $validation['code']);
        }

        return $this->json([
            'actions' => ['LOGIN', 'LOGOUT', 'CREATE', 'UPDATE', 'DELETE']
        ]);
    }
}