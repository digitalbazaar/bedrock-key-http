/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const asyncHandler = require('express-async-handler');
const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const brPassport = require('bedrock-passport');
const brRest = require('bedrock-rest');
const cors = require('cors');
const docs = require('bedrock-docs');

const BedrockError = bedrock.util.BedrockError;
const ensureAuthenticated = brPassport.ensureAuthenticated;
const validate = require('bedrock-validation').validate;

const logger = bedrock.loggers.get('app');

require('./config');

// setup path params
bedrock.events.on('bedrock-express.init', app =>
  app.param('publicKey', brRest.idParam));

// add routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  const keyPath = bedrock.config['key-http'].routes.basePath;

  app.post(keyPath,
    ensureAuthenticated,
    validate('services.key.postKeys'),
    asyncHandler(async (req, res) => {
      logger.warning('FIXME: add checks when adding public key with owner');

      // build public key
      const publicKey = {
        '@context': bedrock.config.constants.SECURITY_CONTEXT_V2_URL,
        type: req.body.type,
        owner: req.body.owner,
        label: req.body.label,
        publicKeyPem: req.body.publicKeyPem
      };

      let privateKey = null;
      if('privateKeyPem' in req.body) {
        privateKey = {
          type: req.body.type.replace('VerificationKey', 'SigningKey'),
          owner: req.body.owner,
          label: req.body.label,
          privateKeyPem: req.body.privateKeyPem
        };
      }

      let record;
      try {
        record = await brKey.addPublicKey(
          {actor: req.user.actor, publicKey, privateKey});
      } catch(e) {
        if(e.name === 'DuplicateError') {
          throw new BedrockError(
            'The public key is a duplicate and could not be added.',
            'DuplicateError', {
              httpStatusCode: 409,
              public: true
            }, e);
        }
        throw new BedrockError(
          'The identity key could not be added.',
          'OperationError', {
            httpStatusCode: 400,
            public: true
          }, e);
      }

      res.set('Location', record.publicKey.id);
      res.status(201).json(record.publicKey);
    }));
  docs.annotate.post(keyPath, {
    description: 'Associate a public key with the identity.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.key.postKeys',
    responses: {
      201: 'Key registration was successful.',
      400: 'The key could not be added.',
      409: 'The key is a duplicate and was not added.'
    }
  });

  // FIXME: 404 if owner unknown vs []?
  // API for getting all keys
  app.options(keyPath, cors());
  app.get(keyPath,
    cors(),
    validate({
      query: 'services.key.getKeysQuery'
    }),
    brRest.when.prefers.ld,
    brRest.linkedDataHandler({
      get: (req, res, callback) => {
        const actor = req.user ? req.user.identity : undefined;
        brKey.getPublicKeys(
          {actor, id: req.query.owner, options: req.query}, (err, records) => {
            if(err) {
              return callback(err);
            }
            callback(err, records ? records.map(r => r.publicKey) : null);
          });
      }
    }));
  // FIXME add owner param docs
  docs.annotate.get(keyPath, {
    description: 'Get the list of public keys associated with an identity.',
    securedBy: ['null', 'cookie', 'hs1'],
    responses: {
      200: {
        'application/ld+json': {
          'example': 'examples/get.identity.keys.jsonld'
        }
      }
    }
  });

  // API for updating a local public key
  app.post(keyPath + '/:publicKey',
    ensureAuthenticated,
    validate('services.key.postKey'),
    asyncHandler(async (req, res) => {
      const publicKeyId = brKey.createPublicKeyId(req.params.publicKey);
      _postPublicKey(publicKeyId, req, res);
    }));
  docs.annotate.post(keyPath + '/:publicKey', {
    description: 'Modify an existing public key.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.key.postKey',
    responses: {
      200: 'The key was revoked successfully.',
      204: 'The key was updated successfully.',
      400: 'The key could not be modified.'
    }
  });

  // API for getting a local public key
  app.options(keyPath + '/:publicKey', cors());
  app.get(keyPath + '/:publicKey',
    cors(),
    brRest.when.prefers.ld,
    brRest.linkedDataHandler({
      get: (req, res, callback) => {
        // get public key
        const publicKey = {id: brKey.createPublicKeyId(req.params.publicKey)};
        brKey.getPublicKey({publicKey}, (err, result) => {
          if(err) {
            return callback(err);
          }
          callback(null, result.publicKey);
        });
      }
    }));
  docs.annotate.get(keyPath + '/:publicKey', {
    description: 'Get a public keys associated with an identity.',
    securedBy: ['null', 'cookie', 'hs1'],
    responses: {
      200: {
        'application/ld+json': {
          'example': 'examples/get.identity.keys.publicKey.jsonld'
        }
      },
      404: 'The key was not found.'
    }
  });
});

async function _postPublicKey(publicKeyId, req, res) {
  if(publicKeyId !== req.body.id) {
    // id mismatch
    throw new BedrockError(
      'Incorrect key id.',
      'URLMismatchError', {
        'public': true,
        httpStatusCode: 400
      });
  }

  if('revoked' in req.body) {
    // revoke public key
    const key = await brKey.revokePublicKey(
      {actor: req.user.actor, publicKeyId});
    return res.status(200).send(key);
  }

  // update public key
  const publicKey = await brKey.getPublicKey({id: publicKeyId});
  if('label' in req.body) {
    publicKey.label = req.body.label;
  }
  await brKey.updatePublicKey({actor: req.user.actor, publicKey});
  res.sendStatus(204);
}
