-- Bad: SELECT * with no WHERE clause
SELECT * FROM users;

-- Bad: Missing WHERE on DELETE
DELETE FROM sessions;

-- Bad: Leading wildcard LIKE
SELECT id, name FROM products WHERE name LIKE '%widget%';

-- Bad: Cartesian join
SELECT u.name, o.total FROM users u, orders o;

-- Bad: OR in WHERE
SELECT * FROM events WHERE status = 'active' OR category = 'urgent';
