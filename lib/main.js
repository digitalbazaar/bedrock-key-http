/*
 * Bedrock Key HTTP Module
 *
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var _ = require('underscore');
var async = require('async');
var bedrock = require('bedrock');
var brKey = require('bedrock-key');
var brPassport = require('bedrock-passport');
var brRest = require('bedrock-rest');
var database = require('bedrock-mongodb');
var cors = require('cors');
var docs = require('bedrock-docs');
var util = require('util');

var BedrockError = bedrock.util.BedrockError;
var ensureAuthenticated = brPassport.ensureAuthenticated;
var validate = require('bedrock-validation').validate;

require('./config');

// add routes
bedrock.events.on('bedrock-express.configure.routes', addRoutes);

function addRoutes(app) {
  var basePath = bedrock.config['key'].basePath;
  var identityBasePath;
  // FIXME: deprecated old key path
  if('idp' in bedrock.config) {
    identityBasePath = bedrock.config.idp.identityBasePath + '/:identity';
  }

  // TODO: determine if this API can be used to create DID-based keys
  app.post(basePath,
    ensureAuthenticated,
    validate('services.key.postKeys'),
    function(req, res, next) {
      // FIXME: handle custom set ids
      var identityId = req.user.identity.id;

      // build public key
      var publicKey = {
        '@context': bedrock.config.constants.IDENTITY_CONTEXT_V1_URL,
        type: 'CryptographicKey',
        owner: identityId,
        label: req.body.label,
        publicKeyPem: req.body.publicKeyPem
      };

      var privateKey = null;
      if('privateKeyPem' in req.body) {
        privateKey = {
          type: 'CryptographicKey',
          owner: identityId,
          label: req.body.label,
          privateKeyPem: req.body.privateKeyPem
        };
      }

      // add public key
      brKey.addPublicKey(
        req.user.identity, publicKey, privateKey, function(err) {
        if(err && database.isDuplicateError(err)) {
          return next(new BedrockError(
            'The identity key is a duplicate and could not be added.',
            'DuplicateIdentityKey', {
              httpStatusCode: 409,
              'public': true
            }));
        }
        if(err) {
          return next(new BedrockError(
            'The identity key could not be added.',
            'AddIdentityKeyFailed', {
              httpStatusCode: 400,
              'public': true
            }, err));
        }
        // return key
        res.set('Location', publicKey.id);
        res.status(201).json(publicKey);
      });
    });
  docs.annotate.post(basePath, {
    description: 'Associate a public key with the identity.',
    securedBy: ['cookie', 'hs1'],
    schema: 'services.key.postKeys',
    responses: {
      201: 'Key registration was successful.',
      400: 'The key could not be added.',
      409: 'The key is a duplicate and was not added.'
    }
  });

  /* FIXME: update for ownerId(?) query vs old path id
  // TODO: determine if DID-based keys should be returned
  // API for getting all keys (including DID-based keys?)
  app.options(basePath, cors());
  app.get(basePath,
    cors(),
    brRest.when.prefers.ld,
    brRest.linkedDataHandler({
      get: function(req, res, callback) {
        async.auto({
          getId: auth.getIdentityIdFromUrl.bind(null, req),
          getKeys: ['getId', function(callback, results) {
            // get keys
            brKey.getPublicKeys(results.getId, function(err, records) {
              if(err) {
                return callback(err);
              }
              callback(err, records ? _.pluck(records, 'publicKey') : null);
            });
          }]
        }, function(err, results) {
          callback(err, results.getKeys);
        });
      }
    }));
  docs.annotate.get(basePath, {
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
  */

  function _postPublicKey(publicKeyId, req, res, next) {
    if(publicKeyId !== req.body.id) {
      // id mismatch
      return next(new BedrockError(
        'Incorrect key id.',
        'KeyIdError', {
          'public': true,
          httpStatusCode: 400
        }));
    }

    if('revoked' in req.body) {
      // revoke public key
      return brKey.revokePublicKey(
        req.user.identity, publicKeyId, function(err, key) {
          if(err) {
            return next(err);
          }
          res.status(200).send(key);
        });
    }

    async.waterfall([
      function(callback) {
        brKey.getPublicKey({id: publicKeyId}, function(err, publicKey) {
          callback(err, publicKey);
        });
      },
      function(key, callback) {
        // update public key
        if('label' in req.body) {
          key.label = req.body.label;
        }
        brKey.updatePublicKey(req.user.identity, key, callback);
      }
    ], function(err) {
      if(err) {
        return next(err);
      }
      res.sendStatus(204);
    });
  }

  // FIXME: support for deprecated old key path
  function _createOldPublicKeyId(req) {
    return util.format('%s%s/%s/keys/%s',
      bedrock.config.server.baseUri,
      bedrock.config.idp.identityBasePath,
      encodeURIComponent(req.params.identity),
      encodeURIComponent(req.params.publicKey));
  }

  // API for updating a local public key
  app.post(basePath + '/:publicKey',
    ensureAuthenticated,
    validate('services.key.postKey'),
    function(req, res, next) {
      // get ID from URL
      var publicKeyId = brKey.createPublicKeyId(req.params.publicKey);
      _postPublicKey(publicKeyId, req, res, next);
    });
  // FIXME: deprecated old key path support
  if(identityBasePath) {
    app.post(identityBasePath + '/keys/:publicKey',
      ensureAuthenticated,
      validate('services.key.postKey'),
      function(req, res, next) {
        // get old ID from URL
        var publicKeyId = _createOldPublicKeyId(req);
        _postPublicKey(publicKeyId, req, res, next);
      });
  }
  docs.annotate.post(basePath+ '/:publicKey', {
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
  app.options(basePath + '/:publicKey', cors());
  app.get(basePath + '/:publicKey',
    cors(),
    brRest.when.prefers.ld,
    brRest.linkedDataHandler({
      get: function(req, res, callback) {
        var publicKeyId = brKey.createPublicKeyId(req.params.publicKey);
        // get public key
        brKey.getPublicKey({id: publicKeyId}, function(err, key) {
          callback(err, key);
        });
      }
    }));
  // FIXME: deprecated old key path support
  if(identityBasePath) {
    app.options(identityBasePath + '/keys/:publicKey', cors());
    app.get(identityBasePath + '/keys/:publicKey',
      cors(),
      brRest.when.prefers.ld,
      brRest.linkedDataHandler({
        get: function(req, res, callback) {
          // get old ID from URL
          var publicKeyId = _createOldPublicKeyId(req);
          // get public key
          brKey.getPublicKey({id: publicKeyId}, function(err, key) {
            callback(err, key);
          });
        }
      }));
  }
  docs.annotate.get(basePath + '/:publicKey', {
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
}

bedrock.events.on('bedrock-views.vars.get', addViewVars);

function addViewVars(req, vars, callback) {
  // FIXME which namespaces?
  vars['key-http'] = {};
  vars['key-http'].basePath = bedrock.config['key'].basePath;
  vars['key-http'].baseUri = vars.baseUri + vars['key-http'].basePath;

  callback();
}

