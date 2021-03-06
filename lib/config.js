/*
 * Bedrock Key HTTP Module Configuration
 *
 * Copyright (c) 2015 Digital Bazaar, Inc. All rights reserved.
 */
var config = require('bedrock').config;
var path = require('path');
require('bedrock-validation');

var keyBasePath = config.key.basePath;
config['key-http'] = {};
config['key-http'].routes = {};
config['key-http'].routes.basePath = keyBasePath;

// common validation schemas
config.validation.schema.paths.push(
  path.join(__dirname, '..', 'schemas')
);

// documentation config
config.docs.categories['/keys'] = 'Key Services';
