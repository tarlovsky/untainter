{
	"kind": "program",
	"children": [
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "nis",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "offsetlookup",
				"what": {
					"kind": "variable",
					"name": "_POST",
					"byref": false,
					"curly": false
				},
				"offset": {
					"kind": "string",
					"value": "nis",
					"isDoubleQuote": false
				}
			}
		},
		{
			"kind": "if",
			"test": {
				"kind": "bin",
				"type": "==",
				"left": {
					"kind": "variable",
					"name": "indarg",
					"byref": false,
					"curly": false
				},
				"right": {
					"kind": "string",
					"value": "",
					"isDoubleQuote": true
				}
			},
			"body": {
				"kind": "block",
				"children": [
					{
						"kind": "if",
						"test": {
							"kind": "bin",
							"type": "==",
							"left": {
								"kind": "variable",
								"name": "indarg",
								"byref": false,
								"curly": false
							},
							"right": {
								"kind": "string",
								"value": "",
								"isDoubleQuote": true
							}
						},
						"body": {
							"kind": "block",
							"children": [
								{
									"kind": "assign",
									"operator": "=",
									"left": {
										"kind": "variable",
										"name": "query",
										"byref": false,
										"curly": false
									},
									"right": {
										"kind": "encapsed",
										"value": [
											{
												"kind": "string",
												"value": "SELECT *FROM siswa WHERE nis='",
												"isDoubleQuote": false
											},
											{
												"kind": "variable",
												"name": "nis",
												"byref": false,
												"curly": false
											},
											{
												"kind": "string",
												"value": "'",
												"isDoubleQuote": false
											}
										],
										"type": "string"
									}
								}
							]
						},
						"alternate": {
							"kind": "block",
							"children": [
								{
									"kind": "assign",
									"operator": "=",
									"left": {
										"kind": "variable",
										"name": "query",
										"byref": false,
										"curly": false
									},
									"right": {
										"kind": "encapsed",
										"value": [
											{
												"kind": "string",
												"value": "SELECT *FROM siswa WHERE nis='",
												"isDoubleQuote": false
											},
											{
												"kind": "variable",
												"name": "indarg",
												"byref": false,
												"curly": false
											},
											{
												"kind": "string",
												"value": "'",
												"isDoubleQuote": false
											}
										],
										"type": "string"
									}
								}
							]
						},
						"shortForm": false
					}
				]
			},
			"alternate": {
				"kind": "block",
				"children": [
					{
						"kind": "assign",
						"operator": "=",
						"left": {
							"kind": "variable",
							"name": "query",
							"byref": false,
							"curly": false
						},
						"right": {
							"kind": "encapsed",
							"value": [
								{
									"kind": "string",
									"value": "SELECT *FROM siswa WHERE nis='",
									"isDoubleQuote": false
								},
								{
									"kind": "variable",
									"name": "indarg",
									"byref": false,
									"curly": false
								},
								{
									"kind": "string",
									"value": "'",
									"isDoubleQuote": false
								}
							],
							"type": "string"
						}
					}
				]
			},
			"shortForm": false
		},
		{
			"kind": "assign",
			"operator": "=",
			"left": {
				"kind": "variable",
				"name": "q",
				"byref": false,
				"curly": false
			},
			"right": {
				"kind": "call",
				"what": {
					"kind": "identifier",
					"resolution": "uqn",
					"name": "mysql_query"
				},
				"arguments": [
					{
						"kind": "variable",
						"name": "query",
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
		}
	],
	"errors": []
}