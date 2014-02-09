#!/usr/bin/env node
var argv = require('optimist').argv,
knock = require('lib.js'),
_ = require('underscore');

_.each(argv._,function doKnock(domain){
knock(domain);
});
