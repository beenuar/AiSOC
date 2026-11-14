-- 059: retire the administrator that migration 001 seeded and nobody could use.
--
-- 001 inserted 'admin@aisoc.local' with a bcrypt hash whose plaintext is not
-- known. The address alone made it unusable — `.local` is an RFC 6761
-- special-use domain and the login route's pydantic `EmailStr` rejects it with
-- a 422 before the password is compared — and the hash matched none of the
-- passwords the documentation published either. 001 no longer seeds it, which
-- covers fresh installs; this covers databases that already ran 001.
--
-- The row is deactivated rather than deleted. Deleting is tempting for a row
-- that was never usable, but `005_compliance.sql` references users(id) with no
-- ON DELETE clause, so a DELETE can fail on a constraint instead of completing
-- quietly — and `is_active = FALSE` is enough: it is what the login route
-- filters on, and what bootstrap_admin.py checks before deciding an
-- administrator already exists.
--
-- Guarded on the id, address and exact hash together so it can only ever match
-- the row 001 wrote. seed_demo.py adopts this same id and rewrites all three
-- columns, so a demo deployment's user does not match and is left alone.

UPDATE users
SET    is_active = FALSE,
       updated_at = NOW()
WHERE  id = '00000000-0000-0000-0000-000000000002'
  AND  email = 'admin@aisoc.local'
  AND  hashed_password = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3EEbF7FtRS'
  AND  last_login IS NULL;
