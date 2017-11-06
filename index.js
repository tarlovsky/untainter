  // initialize the php parser factory class
var fs = require('fs');
var path = require('path');
var engine = require('php-parser');

// initialize a new parser instance
var parser = new engine({
  // some options :
  parser: {
    extractDoc: true
  },
  ast: {
    withPositions: false
  }
});

// Retrieve the AST from the specified source
//var eval = parser.parseEval('echo "Hello World";');

// Retrieve an array of tokens (same as php function token_get_all)
//var tokens = parser.tokenGetAll('<?php echo "Hello World";');

// Load a static file (Note: this file should exist on your computer)

var files=[];
var fnames=[];

process.argv.forEach(function (val, index, array) {
  if(index > 1){
    fnames.push(val)
    files.push(fs.readFileSync( val, "utf-8" ));
  }
});
// Log out results
//console.log( 'Eval parse:', eval );
//console.log( 'Tokens parse:', tokens );
files.forEach(function(ele,i){
  var res = parser.parseCode(ele)
  fs.writeFileSync('ast_'+fnames[i], JSON.stringify(res, null, '\t'))
});