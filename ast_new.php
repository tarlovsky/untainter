{
	"kind": "program",
	"children": [
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "u",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "offsetlookup",
				"what": {
					"kind": "variable",
					"name": "_GET",
					"byref": false,
					"curly": false
				},
				"offset": {
					"kind": "string",
					"value": "u",
					"isDoubleQuote": true
				}
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "p",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "offsetlookup",
				"what": {
					"kind": "variable",
					"name": "_GET",
					"byref": false,
					"curly": false
				},
				"offset": {
					"kind": "string",
					"value": "p",
					"isDoubleQuote": true
				}
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "koneksi",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "call",
				"what": {
					"kind": "identifier",
					"resolution": "uqn",
					"name": "pg_escape_string"
				},
				"arguments": [
					{
						"kind": "offsetlookup",
						"what": {
							"kind": "variable",
							"name": "_GET",
							"byref": false,
							"curly": false
						},
						"offset": {
							"kind": "string",
							"value": "koneksi",
							"isDoubleQuote": true
						}
					}
				]
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "b",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "variable",
				"name": "b",
				"byref": false,
				"curly": false
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "b",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "call",
				"what": {
					"kind": "identifier",
					"resolution": "uqn",
					"name": "pg_escape_string"
				},
				"arguments": [
					{
						"kind": "bin",
						"type": ".",
						"left": {
							"kind": "bin",
							"type": ".",
							"left": {
								"kind": "variable",
								"name": "u",
								"byref": false,
								"curly": false
							},
							"right": {
								"kind": "variable",
								"name": "p",
								"byref": false,
								"curly": false
							}
						},
						"right": {
							"kind": "call",
							"what": {
								"kind": "identifier",
								"resolution": "uqn",
								"name": "pg_escape_string"
							},
							"arguments": [
								{
									"kind": "bin",
									"type": ".",
									"left": {
										"kind": "variable",
										"name": "u",
										"byref": false,
										"curly": false
									},
									"right": {
										"kind": "variable",
										"name": "p",
										"byref": false,
										"curly": false
									}
								}
							]
						}
					}
				]
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "tmp",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "call",
				"what": {
					"kind": "identifier",
					"resolution": "uqn",
					"name": "mysql_escape_string"
				},
				"arguments": [
					{
						"kind": "variable",
						"name": "tmp",
						"byref": false,
						"curly": false
					}
				]
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "tmp",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "call",
				"what": {
					"kind": "identifier",
					"resolution": "uqn",
					"name": "pg_query"
				},
				"arguments": [
					{
						"kind": "variable",
						"name": "b",
						"byref": false,
						"curly": false
					},
					{
						"kind": "variable",
						"name": "koneksi",
						"byref": false,
						"curly": false
					}
				]
			}
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "t",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "parenthesis",
				"inner": {
					"kind": "variable",
					"name": "tmp",
					"byref": false,
					"curly": false
				}
			}
		},
		{
			"kind": "call",
			"what": {
				"kind": "identifier",
				"resolution": "uqn",
				"name": "mysql_query"
			},
			"arguments": [
				{
					"kind": "variable",
					"name": "t",
					"byref": false,
					"curly": false
				}
			]
		},
		{
			"kind": "inline",
			"value": "\n\n"
		}
	],
	"errors": []
}