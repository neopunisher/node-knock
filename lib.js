var _ = require('underscore')._, glob = require('glob'),
tldtools = require('tldtools').init(),
dns = require('dns'), request = require('request'),
Step = require('step'), fs = require('fs'),
dnstest = function(){  },
webtest = function(){  },
basedomain = function(domain){ var res = tldtools.extract(domain).inspect; return res.useful()?res.getDomain():false; }
module.exports.opts = {type:dnstest,types:[dnstest,webtest],verify:true,wildcard:{tests:1,neverthere:'knocknpmknocknpm'}};

//dns.resolve4(domain, cb);

module.exports = function knock(domain,opts,cb){
if (_.isFunction(opts)){
console.log('swaped for cb',module.exports.opts);
cb = opts;
opts = module.export.opts
}else if(_.isOnject(opts)){
opts = _.extend(module.exports.opts,opts)
console.log('extended',opts)
}

var domain = basedomain(domain);
if ( domain === false ) {
cb('invalid domain');
}else{
console.log('basedomain',domain);


}
}
