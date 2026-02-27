-- Good: Explicit columns with WHERE
SELECT id, name, email FROM users WHERE active = 1 LIMIT 100;

-- Good: Explicit JOIN
SELECT u.name, o.total
FROM users u
JOIN orders o ON u.id = o.user_id
WHERE o.created_at > '2025-01-01';
