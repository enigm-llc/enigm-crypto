# Enigm 2.2 V2 Cutover

1. Back up PostgreSQL and export counts for users, contacts, subscriptions, tenants and products.
2. Require the Enigm 2.2 mobile build before authentication can continue.
3. Delete conversations, messages, groups, calls, chat objects and obsolete device cryptographic
   state. Preserve users, contacts and commercial records.
4. Deploy the V2 schema and backend before allowing the 2.2 client through the update gate.
5. Require every active device to generate a fresh V2 identity and signed KEM bundles locally.
6. Clear previous contact-verification state because it referred to retired key material.
7. Consume one-time bundles transactionally and fail closed when exact active-device coverage is
   unavailable.
8. Keep private identity and ratchet state in account-scoped secure storage and delete prior chain
   keys after durable advancement.
9. Run direct, group, attachment, call, membership-rotation, deletion and TTL checks before opening
   production traffic.
10. Do not enable any legacy fallback or timeout downgrade.

Round5 may contribute an additional independently derived secret. V2 security must remain based on
ML-KEM-768, X25519, ML-DSA-65 and Ed25519 when that supplemental contribution is absent.
