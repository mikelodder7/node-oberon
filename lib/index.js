var oberon = require('../native');

var keyPair = oberon.newKeys();

// Can be anything, for demo, its a guid
var id = "1578a909-353e-48f7-b721-6220680f0b67";

var token = oberon.newToken(id, keyPair["secretKey"])

var proof = oberon.newProofTimestamp(token, id, []);