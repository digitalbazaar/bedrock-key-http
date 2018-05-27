/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const config = bedrock.config;
const helpers = require('./helpers');
const mockData = require('./mock.data');
let request = require('request');
request = request.defaults({json: true, strictSSL: false});
const url = require('url');

const urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: config.key.basePath
};

describe('bedrock-key-http API: getPublicKey', () => {
  beforeEach(done => {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    const actor = mockIdentity.identity;

    it('should return a public key for an actor using key id', done => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, privateKey, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(actor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return a public key for another actor using key id', done => {
      const samplePublicKey = {};
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(secondActor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return nothing if key not found', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;

      async.auto({
        insert: callback => brKey.addPublicKey({
          actor: null, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: (samplePublicKey.id + 1),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(404);
          const result = results.get;
          should.exist(result.body);
          result.body.should.be.an('object');
          should.exist(result.body.type);
          result.body.type.should.equal('NotFoundError');
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const actor = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', done => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, privateKey, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(actor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

    it('should return a public key for another actor using key id', done => {
      const samplePublicKey = {};
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondActor.id;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          result.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
          result.owner.should.equal(secondActor.id);
          should.not.exist(result.privateKey);
          callback();
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const actor = mockIdentity.identity;

    it('should return a public key for an actor using key id', done => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = actor.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, privateKey, publicKey: samplePublicKey}, callback),
        get: ['insert', (results, callback) => request.get(
          helpers.createHttpSignatureRequest({
            url: samplePublicKey.id,
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          })],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
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
      request.get(url.format(urlObj), (err, res) => {
        res.statusCode.should.equal(404);
        should.exist(res.body.type);
        res.body.type.should.equal('NotFoundError');
        done();
      });
    });

  }); // no authentication

});
