/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');
const path = require('path');

const {permissions} = config.permission;
const {roles} = config.permission;

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_key_http_test';
config.mongodb.local.collection = 'bedrock_key_http_test';
config.mongodb.dropCollections = {};
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];

roles['bedrock-key-http.test'] = {
  id: 'bedrock-key-http.test',
  label: 'Key HTTP Test Role',
  comment: 'Role for Test User',
  sysPermission: [
    permissions.PUBLIC_KEY_REMOVE.id,
    permissions.PUBLIC_KEY_ACCESS.id,
    permissions.PUBLIC_KEY_CREATE.id,
    permissions.PUBLIC_KEY_EDIT.id
  ]
};
