/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals describe, it, should, beforeEach */
/* jshint node: true */
'use strict';

var async = require('async');
var bedrock = require('bedrock');
var config = bedrock.config;
var database = require('bedrock-mongodb');
var helpers = require('./helpers');
var mockData = require('./mock.data');
var request = require('request');
request = request.defaults({json: true, strictSSL: false});
var url = require('url');

var urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: config.key.basePath
};

describe('bedrock-key-http API: addPublicKey', function() {
  beforeEach(function(done) {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    var actor = mockData.identities.regularUser;

    it('should add a valid public key with no private key', done => {
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: function(callback) {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
          });
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(201);
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

    it('should add a valid public key with matching private key', done => {
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: function(callback) {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
          });
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(201);
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.exist(result[1].publicKey.privateKey);
            result[1].publicKey.privateKey.privateKeyPem.should.equal(
              newKey.privateKeyPem);
            callback();
          });
        }]
      }, done);
    });

    it('should return error if adding public key w/ bad private key', done => {
      var newKey = mockData.badKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: function(callback) {
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('InvalidKeyPair');
          callback();
        }]
      }, done);
    });

    it('should return error if owner id does not match', done => {
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id + 1,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: function(callback) {
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('PermissionDenied');
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    var actor = mockData.identities.adminUser;

    it('should add a valid public key for self', done => {
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: function(callback) {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
          });
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(201);
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

    it('should add a valid public key for another user', done => {
      var actor2 = mockData.identities.regularUser;
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor2.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: function(callback) {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
          });
          database.collections.publicKey.find({
            'publicKey.owner': actor2.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor2.keys.publicKey.publicKeyPem);
          });
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(201);
          database.collections.publicKey.find({
            'publicKey.owner': actor2.identity.id
          }).toArray(function(err, result) {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    var actor = mockData.identities.noPermissionUser;

    it('should return error when adding public key w/o permissions', done => {
      var newKey = mockData.goodKeyPair;
      var samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: function(callback) {
          request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['insert', function(callback, results, err) {
          should.not.exist(err);
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('PermissionDenied');
          callback();
        }]
      }, done);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return error when not authenticated', done => {
      request.post(url.format(urlObj), function(err, res, body) {
        res.statusCode.should.equal(400);
        should.exist(body);
        body.should.be.an('object');
        should.exist(body.type);
        body.type.should.equal('PermissionDenied');
        done();
      });
    });

  }); // no authentication

});
