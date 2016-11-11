/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals describe, it, should, beforeEach */
/* jshint node: true */
'use strict';

var async = require('async');
var bedrock = require('bedrock');
var brKey = require('bedrock-key');
var config = bedrock.config;
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

describe('bedrock-key-http API: getPublicKey', function() {
  beforeEach(done => {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    var mockIdentity = mockData.identities.regularUser;
    var actor = mockIdentity.identity;

    it('should return a public key for an actor using key id', done => {
      var samplePublicKey = {};
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(actor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return a public key for another actor using key id', done => {
      var samplePublicKey = {};
      var mockIdentity2 = mockData.identities.regularUser2;
      var secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(secondActor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return nothing if key not found', done => {
      var samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: (samplePublicKey.id + 1),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(404);
          var result = results.get;
          should.exist(result.body);
          result.body.should.be.an('object');
          should.exist(result.body.type);
          result.body.type.should.equal('NotFound');
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    var mockIdentity = mockData.identities.adminUser;
    var actor = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', done => {
      var samplePublicKey = {};
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(actor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return a public key for another actor using key id', done => {
      var samplePublicKey = {};
      var mockIdentity2 = mockData.identities.regularUser2;
      var secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(secondActor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    var mockIdentity = mockData.identities.noPermissionUser;
    var actor = mockIdentity.identity;

    it('should return a public key for an actor using key id', done => {
      var samplePublicKey = {};
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
        },
        get: ['insert', callback => {
          request.get(helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(actor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

  }); // noPermissionUser

  describe('User with no authentication', () => {

    it('should return error for nonauthenticated ID (no Key)', done => {
      urlObj.pathname += '/99';
      request.get(url.format(urlObj), function(err, res, body) {
        res.statusCode.should.equal(404);
        should.exist(res.body.type);
        res.body.type.should.equal('NotFound');
        done();
      });
    });

  }); // no authentication

});
