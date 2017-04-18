/*
 * Bedrock Key HTTP Module Test Configuration.
 *
 * Copyright (c) 2012-2017 Digital Bazaar, Inc. All rights reserved.
 */
const config = require('bedrock').config;
const path = require('path');

const permissions = config.permission.permissions;
const roles = config.permission.roles;

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
