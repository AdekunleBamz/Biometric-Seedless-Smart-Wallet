;; Biometric Seedless Smart Wallet
;; Implements non-custodial wallet using secp256r1-verify (Clarity 4)
;;
;; This smart contract provides a seedless authentication mechanism using
;; secp256r1 elliptic curve signatures. Users can authenticate using
;; biometric data stored on their device without exposing seed phrases.
;;
;; Security Properties:
;; - No seed phrases required - uses device-based keys
;; - Non-custodial - users retain full control
;; -Nonce-based replay protection
;; - Single initialization for security

;; Data Variables
;; Owner public key (compressed secp256r1 format - 33 bytes)
(define-data-var owner-pubkey (buff 33) 0x00)

;; Nonce for replay attack prevention
(define-data-var nonce uint u0)

;; Initialization flag to ensure wallet is set up
(define-data-var initialized bool false)

;; Contract owner for admin functions (set at deployment)
(define-data-var contract-owner principal tx-sender)

;; Error Constants
(define-constant ERR-INVALID-SIGNATURE (err u100))
(define-constant ERR-INVALID-NONCE (err u101))
(define-constant ERR-UNAUTHORIZED (err u102))
(define-constant ERR-ALREADY-INITIALIZED (err u103))
(define-constant ERR-NOT-INITIALIZED (err u104))
(define-constant ERR-ZERO-PUBKEY (err u105))
(define-constant ERR-RESET-NOT-AUTHORIZED (err u106))

;; Initialize the wallet with owner's public key
;; This can only be called once to set the initial owner
;;
;; Arguments:
;; - new-owner-pubkey: Compressed secp256r1 public key (33 bytes)
;;
;; Returns:
;; - (ok true) on success
;; - Error code if already initialized
;;
;; Security:
;; - Can only be called once
;; - After initialization, the owner key cannot be changed
(define-public (initialize (new-owner-pubkey (buff 33)))
    (begin
        ;; Ensure not already initialized
        (asserts! (not (var-get initialized)) ERR-ALREADY-INITIALIZED)
        
        ;; Validate public key is not empty
        (asserts! (> (len new-owner-pubkey) u0) ERR-ZERO-PUBKEY)
        
        ;; Set the owner public key
        (var-set owner-pubkey new-owner-pubkey)
        
        ;; Mark as initialized
        (var-set initialized true)
        
        (ok true)
    )
)

;; Get the current nonce value
;; Used for replay attack prevention
;;
;; Returns:
;; - Current nonce value
(define-read-only (get-nonce)
    (ok (var-get nonce))
)

;; Get the owner's public key
;;
;; Returns:
;; - Owner's compressed public key
(define-read-only (get-owner-pubkey)
    (ok (var-get owner-pubkey))
)

;; Check if wallet has been initialized
;;
;; Returns:
;; - True if initialized, false otherwise
(define-read-only (is-initialized)
    (ok (var-get initialized))
)

;; Verify a signature without executing an action
;; Useful for authentication purposes
;;
;; Arguments:
;; - hash: The hash that was signed
;; - signature: The secp256r1 signature (64 bytes)
;;
;; Returns:
;; - True if signature is valid
(define-read-only (verify-signature (hash (buff 32)) (signature (buff 64)))
    (secp256r1-verify hash signature (var-get owner-pubkey))
)

;; Execute an authenticated action
;; Verifies signature and increments nonce to prevent replay attacks
;;
;; Arguments:
;; - action-payload: The action data to execute
;; - signature: The secp256r1 signature (64 bytes)
;;
;; Returns:
;; - (ok "Action executed successfully") on success
;; - Error code on failure
;;
;; Security:
;; - Uses nonce to prevent replay attacks
;; - Verifies secp256r1 signature before execution
;; - Nonce is incremented after each successful execution
(define-public (execute-action (action-payload (buff 128)) (signature (buff 64)))
    (let
        (
            (current-nonce (var-get nonce))
            ;; Create message hash including nonce to prevent replay
            (message-hash (sha256 (unwrap-panic (to-consensus-buff? { 
                payload: action-payload, 
                nonce: current-nonce 
            }))))
        )
        ;; Ensure wallet is initialized
        (asserts! (var-get initialized) ERR-NOT-INITIALIZED)
        
        ;; Verify the signature matches the message hash
        (asserts! (secp256r1-verify message-hash signature (var-get owner-pubkey)) ERR-INVALID-SIGNATURE)
        
        ;; Increment nonce to prevent replay attacks
        (var-set nonce (+ current-nonce u1))
        
        ;; Execute action (placeholder for custom logic)
        ;; In a full implementation, this would parse and execute the action
        
        (ok "Action executed successfully")
    )
)

;; Get the contract owner
;;
;; Returns:
;; - The contract owner principal
(define-read-only (get-contract-owner)
    (ok (var-get contract-owner)))

;; Transfer contract ownership
;; Only the current contract owner can transfer ownership
;;
;; Arguments:
;; - new-owner: The principal to transfer ownership to
;;
;; Returns:
;; - (ok true) on success
;; - Error code if unauthorized
(define-public (transfer-ownership (new-owner principal))
    (begin
        ;; Only allow current owner to transfer
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-UNAUTHORIZED)
        ;; Set new owner
        (var-set contract-owner new-owner)
        (ok true)
    )
)

;; Reset nonce (emergency function)
;; Only the contract deployer can reset the nonce in emergency situations
;; This is a security-critical function that should be used sparingly
;;
;; Returns:
;; - (ok true) on success
;; - Error code if unauthorized
(define-public (reset-nonce)
    (begin
        ;; Only allow contract deployer to reset nonce
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-RESET-NOT-AUTHORIZED)
        (var-set nonce u0)
        (ok true)
    )
)
