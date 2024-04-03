// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to certify a key that is loaded into the TPM.
 *
 * Certification involves two major steps. Using the TPM's endorsement key to create
 * an attestation key. Then using the attestation key to certify other objects in
 * the TPM.
 *
 *
 */

use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        cipher::Cipher,
        ek::{create_ek_public_from_default_template, retrieve_ek_pubcert},
        AsymmetricAlgorithmSelection,
    },
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        reserved_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        CreatePrimaryKeyResult, Data, Digest, EccPoint, EccScheme, HashScheme, MaxBuffer,
        PublicBuilder, PublicEccParametersBuilder, SignatureScheme, SymmetricCipherParameters,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::Marshall,
    Context, TctiNameConf,
};

use std::convert::{TryFrom, TryInto};

fn main() {
    env_logger::init();
    // Create a pair of TPM's contexts - It's not "perfect" but it's what we will use
    // to represent the two TPM's in our test.
    //
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager.
    let mut context_1 = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    let mut context_2 = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    // First we need the endorsement key. This is bound to the manufacturer of the TPM
    // and will serve as proof that the TPM is trustworthy.

    // Depending on your TPM, it may support different algorithms. Rsa2048 and Ecc384
    // are common endorsement key algorithms.
    //
    // Remember, the Hash alg in many cases has to match the key type, especially
    // with ecdsa.

    // == RSA
    // let ek_alg = AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::RsaPss;
    // let sig_scheme = SignatureScheme::RsaPss {
    //     scheme: HashScheme::new(hash_alg),
    // };

    // == ECDSA P384
    let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384);
    let hash_alg = HashingAlgorithm::Sha384;
    let sign_alg = SignatureSchemeAlgorithm::EcDsa;
    let sig_scheme = SignatureScheme::EcDsa {
        scheme: HashScheme::new(hash_alg),
    };

    // == ECDSA P256
    // let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::EcDsa;
    // let sig_scheme = SignatureScheme::EcDsa {
    //    scheme: HashScheme::new(hash_alg),
    // };

    // If you wish to see the EK cert, you can fetch it's DER here.
    let ek_pubcert = retrieve_ek_pubcert(&mut context_1, ek_alg).unwrap();

    // Alternately on the CLI you can view the certificate with:
    // # tpm2_getekcertificate | openssl x509 -inform DER -noout -text

    eprintln!("ek_pubcert der: {:x?}", ek_pubcert);

    // Retrieve the EK public template that allows us to access a handle to the EK
    let ek_template = create_ek_public_from_default_template(ek_alg, None).unwrap();

    // Get the EK handle by loading our template.
    let ek_handle = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_template, None, None, None, None)
        })
        .expect("Failed to load ek_template")
        .key_handle;

    // Get the specific public value of our EK
    let (ek_public, _name, _qualified_name) = context_1
        .read_public(ek_handle)
        .expect("Failed to read ek_public");

    // Now, create our AIK. The AIK in theory does not need to be in the same hierachy as
    // the EK, it only needs to be in the same *TPM*. However in reality, using the create_ak
    // and load_ak functions only works if you use the key in the endorsement hierarchy.
    let ak_create_result = create_ak(
        &mut context_1,
        ek_handle.clone(),
        hash_alg,
        ek_alg,
        sign_alg,
        None,
        None,
    )
    .expect("Failed to create attestation key");

    let ak_public = ak_create_result.out_public.clone();

    // For later, we'll load the AIK now and save it's context.
    let ak_handle = load_ak(
        &mut context_1,
        ek_handle.clone(),
        None,
        ak_create_result.out_private,
        ak_create_result.out_public,
    )
    .expect("Failed to load attestation key");

    let ak_context = context_1
        .execute_with_nullauth_session(|ctx| ctx.context_save(ak_handle.clone().into()))
        .expect("Failed to save ak context");

    context_1
        .flush_context(ak_handle.into())
        .expect("Unable to flush ak_handle");

    // For now to save resources, we save the ek context.
    let ek_context = context_1
        .execute_with_nullauth_session(|ctx| ctx.context_save(ek_handle.into()))
        .expect("Failed to save ek context");

    context_1
        .flush_context(ek_handle.into())
        .expect("Unable to flush ek_handle");

    // ================================================================================
    // At this point we have what we need: The EK X509 DER, EK Public and AIK public for the
    // certifying authority. They are in the corresponding variables right now.

    // ek_pubcert
    // ek_public
    // ak_public

    // Here, the authority should validate that the EK X509 DER is from a trusted authority,
    // the the EK public key matches the public key from EK X509 DER.

    // In our example, we will be taking the trust approach known as "yolo" by verifying none
    // of these details. This is considered unwise in production. Do not be like me.

    // Load the AIK public, and derive it's "name". This will be used as part of the
    // challenge encryption.
    let (_public, ak_name, _qualified_name) = context_2
        .execute_with_nullauth_session(|ctx| {
            let ak_handle = ctx.load_external_public(ak_public.clone(), Hierarchy::Null)?;
            let r = ctx.read_public(ak_handle);
            ctx.flush_context(ak_handle.into())?;
            r
        })
        .expect("Unable to read AIK public");

    // We now create our challenge that we will encrypt. We use 16 bytes (128bit) for
    // a sufficiently random value.
    //
    // Importantly, the authority MUST persist this value for verification in a future
    // step. This value should not be disclosed!
    let challenge = context_2
        .get_random(16)
        .expect("Unable to access random data.");

    // Now we load the ek_public, and create our encrypted challenge.
    let (idobject, encrypted_secret) = context_2
        .execute_with_nullauth_session(|ctx| {
            let ek_handle = ctx.load_external_public(ek_public, Hierarchy::Null)?;
            let r = ctx.make_credential(ek_handle, challenge.clone(), ak_name);
            ctx.flush_context(ek_handle.into())?;
            r
        })
        .expect("Unable to create encrypted challenge");

    // Great! We now have the encrypted challenges to be returned to the first TPM.

    // ================================================================================
    // The values idobject and encrypted_secret and securly returned to the first TPM.
    // We now load and decrypt these to prove that the AIK must be loaded in the TPM
    // that also contains this EK. This is how the trust chain is built.
    let ek_handle = context_1
        .context_load(ek_context)
        .expect("Failed to restore EK context");

    let ak_handle = context_1
        .context_load(ak_context)
        .expect("Failed to restore AIK context");

    // We need two sessions here. One session to authenticate the the EK, and one
    // for the AIK
    let session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap()
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context_1
        .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        .unwrap();

    // Create a session that is capable of performing endorsements.
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    let policy_auth_session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Invalid session attributes.")
        .unwrap();

    context_1
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let _ = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                PolicySession::try_from(policy_auth_session).unwrap(),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    let response = context_1
        .execute_with_sessions((Some(session), Some(policy_auth_session), None), |ctx| {
            ctx.activate_credential(
                ak_handle.clone().into(),
                ek_handle.clone().into(),
                idobject,
                encrypted_secret,
            )
        })
        .unwrap();

    context_1.clear_sessions();

    // At this point we no longer need the EK loaded. We want to keep the AIK loaded for
    // the certify operation we will perform shortly.
    context_1
        .flush_context(ek_handle.into())
        .expect("Failed to unload EK");

    // ================================================================================
    // The response is now sent back to the authority which can verify the response
    // is identical to challenge. If this is the case, the authority can now persist
    // the AIK public for use in future certify operations.
    assert_eq!(challenge, response);

    // ================================================================================

    // Create the key we wish to certify.
    let key_handle = create_key(&mut context_1);

    // This is added to the "extra_data" field of the attestation object. Some uses of this
    // include in Webauthn where this qualifying data contains the sha256 hash of other data
    // that is being authenticated in the operation.
    let qualifying_data: Data = vec![1, 2, 3, 4, 5, 6, 7, 8].try_into().unwrap();

    let session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap()
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context_1
        .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        .unwrap();

    // Create a session that is capable of performing endorsements.
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    let policy_auth_session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Invalid session attributes.")
        .unwrap();

    context_1
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let _ = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                PolicySession::try_from(policy_auth_session).unwrap(),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    let (attest, signature) = context_1
        .execute_with_sessions(
            (
                // The first session authenticates the "object to certify".
                Some(session),
                // This authenticates the attestation key.
                Some(policy_auth_session),
                None,
            ),
            |ctx| {
                ctx.certify(
                    key_handle.into(),
                    ak_handle.into(),
                    qualifying_data,
                    sig_scheme,
                )
            },
        )
        .unwrap();

    println!("attest: {:?}", attest);
    println!("signature: {:?}", signature);

    // ================================================================================
    // Now back on our certifying authority, we want to assert that the attestation we
    // recieved really did come from this TPM. We can use the AIK to demonstrate this
    // linkage, to trust that the object must come from a valid TPM that we trust to
    // behave in a certain manner.

    // First, load the public from the aik
    let ak_handle = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.load_external_public(
                ak_public,
                // We put it into the null hierachy as this is ephemeral.
                Hierarchy::Null,
            )
        })
        .expect("Failed to load aik public");

    let attest_data: MaxBuffer = attest
        .marshall()
        .expect("Unable to marshall")
        .try_into()
        .expect("Data too large");

    let (attest_digest, _ticket) = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.hash(attest_data, HashingAlgorithm::Sha256, Hierarchy::Null)
        })
        .expect("Failed to digest attestation output");

    let verified_ticket = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.verify_signature(ak_handle, attest_digest, signature)
        })
        .expect("Failed to verify attestation");

    println!("verification: {:?}", verified_ticket);
}

fn create_key(context: &mut Context) -> KeyHandle {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let primary = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap();

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // The key is used only for signing.
        .with_sign_encrypt(true)
        .build()
        .expect("Failed to build object attributes");

    let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()
    .expect("Failed to build ecc params");

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap();

    context
        .execute_with_nullauth_session(|ctx| {
            let (private, public) = ctx
                .create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))?;
            let key_handle = ctx.load(primary.key_handle, private, public)?;
            // Unload the primary to make space for objects.
            ctx.flush_context(primary.key_handle.into())
                // And return the key_handle.
                .map(|()| key_handle)
        })
        .unwrap()
}
