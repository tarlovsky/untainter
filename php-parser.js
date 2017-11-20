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
  

  process.argv.forEach(function (val, index, array) {
    if(index > 1){  
      var content = fs.readFileSync( val, "utf-8" )
      console.log("Opened and parsed file: "+val);
      var res = parser.parseCode(content)
      fs.writeFileSync('ast_'+val, JSON.stringify(res, null, '\t'))

      fs.watch(val, { encoding: 'buffer' }, (eventType, filename) => {
        if (filename) {
          var content = fs.readFileSync( val, "utf-8" )
          console.log("Writing changes: "+filename);
          var res = parser.parseCode(content)
          fs.writeFileSync('ast_'+val, JSON.stringify(res, null, '\t'))
        }
      });
    }
  });
 