-- QUICK INSERT: 1000 Dummy OAuth2 Requests
-- Copy and paste this entire block into your database client (pgAdmin, DBeaver, etc.)
-- Or run: psql -U dhaval -d YOUR_DATABASE_NAME -f QUICK_INSERT.sql

-- First, find your developer and client IDs (run these separately first):
-- SELECT id, email FROM developers WHERE normalized_email = 'DHAVALDER93@GMAIL.COM';
-- SELECT client_id, name FROM developer_oauth_clients WHERE developer_id = (SELECT id FROM developers WHERE normalized_email = 'DHAVALDER93@GMAIL.COM' LIMIT 1);

-- Then replace :DEV_ID, :CLIENT_ID, and :USER_ID in the script below with actual values
-- OR use the automatic version below that finds them automatically

-- ============================================
-- AUTOMATIC VERSION (Finds IDs automatically)
-- ============================================

DO $$
DECLARE
    dev_id bytea;
    client_id_val text;
    user_id_val bytea;
    i integer;
    status_val integer;
    redirect_uris text[] := ARRAY[
        'http://localhost:3000/callback',
        'https://example.com/callback',
        'http://localhost:8080/callback',
        'https://app.example.com/oauth/callback',
        'https://myapp.com/oauth/callback',
        'http://localhost:5000/callback',
        'https://testapp.com/callback',
        'https://demo.example.com/callback'
    ];
    scopes_list text[] := ARRAY[
        'read',
        'write',
        'read,write',
        'read,write,list',
        'read,write,delete',
        'read,list',
        'write,delete'
    ];
    rejection_reasons text[] := ARRAY[
        'Invalid redirect URI',
        'Unauthorized scopes requested',
        'User denied access',
        'Security violation',
        'Client validation failed',
        'Expired request',
        'Invalid client credentials'
    ];
    request_id uuid;
    created_time timestamp;
    redirect_uri_val text;
    scopes_val text;
    approved_scopes_val text;
    rejected_scopes_val text;
    code_val text;
BEGIN
    -- Get developer ID for dhavalder93@gmail.com
    SELECT id INTO dev_id FROM developers WHERE normalized_email = 'DHAVALDER93@GMAIL.COM' LIMIT 1;
    
    IF dev_id IS NULL THEN
        RAISE EXCEPTION 'Developer with email dhavalder93@gmail.com not found. Please check the email or create the developer first.';
    END IF;
    
    -- Get first client for this developer
    SELECT doc.client_id INTO client_id_val 
    FROM developer_oauth_clients doc 
    WHERE doc.developer_id = dev_id 
    LIMIT 1;
    
    IF client_id_val IS NULL THEN
        RAISE EXCEPTION 'No OAuth clients found for developer. Please create an OAuth client first.';
    END IF;
    
    -- Get user ID (use developer ID if no users)
    SELECT id INTO user_id_val FROM users LIMIT 1;
    IF user_id_val IS NULL THEN
        user_id_val := dev_id;
    END IF;
    
    RAISE NOTICE 'Inserting 1000 OAuth2 requests...';
    RAISE NOTICE 'Developer ID: %', dev_id;
    RAISE NOTICE 'Client ID: %', client_id_val;
    RAISE NOTICE 'User ID: %', user_id_val;
    
    -- Insert 1000 requests
    FOR i IN 1..1000 LOOP
        -- Determine status: ~20% pending, ~60% approved, ~20% rejected
        IF i % 10 <= 1 THEN
            status_val := 0; -- pending (20%)
        ELSIF i % 10 <= 7 THEN
            status_val := 1; -- approved (60%)
        ELSE
            status_val := 2; -- rejected (20%)
        END IF;
        
        -- Generate random request ID
        request_id := gen_random_uuid();
        
        -- Random timestamp between 30 days ago and now
        created_time := NOW() - (RANDOM() * INTERVAL '30 days');
        
        -- Random redirect URI and scopes
        redirect_uri_val := redirect_uris[1 + floor(random() * array_length(redirect_uris, 1))::int];
        scopes_val := scopes_list[1 + floor(random() * array_length(scopes_list, 1))::int];
        
        -- Set approved/rejected scopes and code based on status
        IF status_val = 1 THEN
            -- Approved: set approved_scopes and code
            approved_scopes_val := scopes_val;
            rejected_scopes_val := '';
            code_val := 'code_' || LPAD(i::text, 6, '0');
        ELSIF status_val = 2 THEN
            -- Rejected: set rejected_scopes with reason
            approved_scopes_val := '';
            rejected_scopes_val := rejection_reasons[1 + floor(random() * array_length(rejection_reasons, 1))::int];
            code_val := '';
        ELSE
            -- Pending: empty everything
            approved_scopes_val := '';
            rejected_scopes_val := '';
            code_val := '';
        END IF;
        
        -- Insert the request
        INSERT INTO oauth2_requests (
            id, client_id, user_id, redirect_uri, scopes, status,
            created_at, consent_expires_at, code, code_expires_at,
            approved_scopes, rejected_scopes
        ) VALUES (
            request_id::bytea,
            client_id_val,
            user_id_val,
            redirect_uri_val,
            scopes_val,
            status_val,
            created_time,
            created_time + INTERVAL '1 hour',
            code_val,
            created_time + INTERVAL '1 hour',
            approved_scopes_val,
            rejected_scopes_val
        );
        
        -- Progress indicator every 100 records
        IF i % 100 = 0 THEN
            RAISE NOTICE 'Inserted % records...', i;
        END IF;
    END LOOP;
    
    RAISE NOTICE '✅ Successfully inserted 1000 OAuth2 requests!';
END $$;

-- Show summary
SELECT 
    '📊 Summary' as info,
    COUNT(*)::text as total,
    COUNT(*) FILTER (WHERE status = 0)::text as pending,
    COUNT(*) FILTER (WHERE status = 1)::text as approved,
    COUNT(*) FILTER (WHERE status = 2)::text as rejected
FROM oauth2_requests
INNER JOIN developer_oauth_clients ON oauth2_requests.client_id = developer_oauth_clients.client_id
WHERE developer_oauth_clients.developer_id = (SELECT id FROM developers WHERE normalized_email = 'DHAVALDER93@GMAIL.COM' LIMIT 1);

