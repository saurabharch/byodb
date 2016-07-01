'use strict';

// OB: This file is huge! Before going any deeper a couple quick thoughts for reining it in
// 1) Split this out into multiple routers.
// 2) Move as much of the logic as possible into the models (not necessarily sequelize models) or other utilities.
// 3) This is the third point in the list.

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
var Sequelize = require('sequelize');
var knex = require('knex');
var pg = require('pg');


module.exports = router;



//get all the information from the association table
// OB: I'm thinking this should instead be /:dbName/assocations, associations are the "subresource" of the database
router.get('/allassociations/:dbName', function(req, res, next) {
    // OB: this could be a model method on Database, something like, .toClientDB()
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })

    // OB: I'm thinking if the table doesn't exist you should throw an error instead of creating it
    knex.schema.createTableIfNotExists(req.params.dbName + '_assoc', function(table) {
            table.increments();
            table.string('Table1');
            table.string('Relationship1');
            table.string('Alias1');
            table.string('Table2');
            table.string('Relationship2');
            table.string('Alias2');
            table.string('Through');
        })
        .then(function() {
            // OB: nested .thens!
            knex.select().table(req.params.dbName + '_assoc')
                .then(function(result) {
                    console.log(result); // OB: chuck these logs like some kind of log chucking animal, maybe a woodchuck?
                    res.send(result);
                })
        })
    // OB: don't forget to handle errors, i.e. here you could have a .catch(next) to forward any knex errors through to your express error handling middleware
})

//get information from the association table for a single table
// OB: I'm thinking this could be /:dbName/tables/:tableName/associations, I think this would better fit expected standards
router.get('/associationtable/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })

    // OB: again, this could be a model method for the some not-yet-defined ClientDB model, or even better an Association model
    knex(req.params.dbName + '_assoc').where(function() {
            this.where('Table1', req.params.tableName).orWhere('Table2', req.params.tableName)
        })
        .then(function(result) {
            console.log(result); // OB: deforestation
            res.send(result);
        })
})

// delete a db
router.delete('/:dbn', function(req, res) {
    // OB: it'd be awesome to just be able to do ClientDB.removeByName(...) or potentially ClientDB.findByName(...).then(function (clientDB) {return clientDB.remove();});
    var pg = require('pg');

    var conString = 'postgres://localhost:5432/masterDB';

    var client = new pg.Client(conString);
    // OB: however you decide to do it, I'd say this is too much logic happening inside your route handler, port it to somewhere else
    client.connect(function(err) {
        if (err) {
            console.log(err) // OB: you could instead forward this onto your express error handling middleware by doing next(err)
            res.send('could not connect to postgres'); // OB: might as well give this a 500 status
        }
        client.query("REVOKE CONNECT ON DATABASE " + req.params.dbn + " FROM public", function(err, result) {
            if (err) {
                console.log('err')
                res.send('error running query');
            }
        });
        client.query("ALTER DATABASE " + req.params.dbn + " CONNECTION LIMIT 0 ", function(err, result) {
            if (err) {
                console.log(err)
                res.send('error running query');
            }
        });
        client.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid()", function(err, result) {
            if (err) {
                console.log(err)
                res.send('error running query');
            }
        });
        client.query("DROP DATABASE " + req.params.dbn, function(err, result) {
            if (err) {
                console.log(err)
                res.send('error running query');
            }
            // OB: missing else
            res.set("Content-Type", 'text/javascript'); //avoid the "Resource interpreted as Script but transferred with MIME type text/html" message
            res.send(result);
            client.end();
        });
    });

});

// OB: I'm thinking POST to /api/clientdb create a database, and it should be POST /api/clientdb/:dbName/tables to create a table
router.post('/', function(req, res, next) {
    if (!req.user) res.sendStatus(404);
    // OB: missing else

    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.body.dbName,
        searchPath: 'knex,public'
    });

    knex.schema.createTable(req.body.name, function(table) {
            table.increments();
            for (var key in req.body.column) {
                table[req.body.type[key]](req.body.column[key]) // OB: this is pretty cool, and also watch out for possible injection abuse
            }
            table.timestamps();
        }).then(function() {
            return knex(req.body.name).insert([
                { id: 1 },
            ]);
        })
        .catch(next);
})

//route to get all tables from a db
// DO WE NEED TO INCLUDE SOMETHING TO HANDLE INJECTION ATTACK? OB: PROBABLY?
// OB: this is for getting all tables yes? if so I'm thinking the matching URL fragment should be /:dbName/tables
router.get('/:dbName', function(req, res) {
    var pg = require('pg');

    var conString = 'postgres://localhost:5432/' + req.params.dbName;

    var client = new pg.Client(conString);
    client.connect(function(err) {
        if (err) {
            res.send('could not connect to postgres');
        }
        client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'", function(err, result) {
            if (err) {
                res.send('error running query');
            }
            // OB: the type is javascript?
            res.set("Content-Type", 'text/javascript'); //avoid the "Resource interpreted as Script but transferred with MIME type text/html" message
            res.send(result);
            client.end();
        });
    });

});

//route to get a single table from a db
// DO NEED TO COME UP WITH A WAY TO REMOVE SPACES FROM THE TABLE NAME WHEN IT GETS SAVED? OB: PROBABLY?
// OB: again, I'm thinking /:dbName/tables/:tableName is closer to standard, or in this case /:dbName/tables/:tableName/rows could be better, because it's really the rows you're GETing
router.get('/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });

    knex.select().from(req.params.tableName)
        .then(function(foundTable) {
            res.send(foundTable)
        })
        .catch(next);
})

//route to query a single table (filter)
// OB: this should be a GET, PUT should only be for updates. that means you'll have to pass the column, comparator, and value through the req.query because GET requests don't have a body.
router.put('/:dbName/:tableName/filter', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })
    knex(req.params.tableName).where(req.body.column, req.body.comparator, req.body.value) // OB: beware possible injection abuse
        .then(function(result) {
            console.log(result); // OB: x
            res.send(result)
        })
        .catch(next); // OB: nice!
})

//route to update data in a table (columns and rows)
// OB: I vote you split this into two route handlers: PUT /:dbName/tables/:tableName/columns/:columnName can update column stuff and PUT /:dbName/tables/:tableName/rows/:rowKey for updating a particular row
router.put('/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })
    var promises = [];
    req.body.rows.forEach(function(row) { // OB: updating multiple rows at once?
        var promise = knex(req.params.tableName)
            .where('id', '=', row.id)
            .update(row)

        promises.push(promise)
    })
    Promise.all(promises)
        .then(function(result) {
            var promises2 = [];
            req.body.columns.forEach(function(column) { // OB: updating multiple columns at once?
                var promise2 = knex.schema.table(req.params.tableName, function(table) {
                    var oldVal = column.oldVal;
                    var newVal = column.newVal;
                    table.renameColumn(oldVal, newVal)
                })
                promises2.push(promise2);
            })
            Promise.all(promises2)
        })
        .then(function() {
            res.sendStatus(200);
        })
        .catch(next);
})

// delete row in table
router.delete('/:dbName/:tableName/:rowId', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });
    knex(req.params.tableName)
        .where('id', req.params.rowId)
        .del()
        .then(function() {
            // OB: nested .thens!
            knex.select().from(req.params.tableName)
                .then(function(foundTable) {
                    res.send(foundTable)
                })
        })
        .catch(next);
})

// delete column in table
router.delete('/:dbName/:tableName/column/:columnName', function(req, res, next) {
    // OB: I haven't been counting exactly but this code has repeated like a bunch of times—definitely excellent refactoring opportunity here
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });
    knex.schema.table(req.params.tableName, function(table) {
            table.dropColumn(req.params.columnName) // OB: is this operation asynchronous?
        })
        .then(function(res) {
            return knex.select().from(req.params.tableName)
        })
        .then(function(foundTable) {
            res.send(foundTable)
        })
        .catch(next);
})

// OB: recommendation is /:dbName/tables/:tableName/rows
router.post('/addrow/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });
    knex(req.params.tableName).insert({ id: req.body.rowNumber })
        .then(function() {
            // OB: nested .thens!
            knex.select().from(req.params.tableName)
                .then(function(foundTable) {
                    console.log(foundTable)
                    res.send(foundTable)
                })
        })
        .catch(next);
})

// OB: having a "verb" in your route should be a red flag. sometimes it's happens, but it's usually considered best practice for the URL to be nouns only and the action is specified by GET/POST/PUT/DELETE etc.
router.post('/addcolumn/:dbName/:tableName/:numNewCol', function(req, res, next) {
    var pg = require('pg');

    var conString = 'postgres://localhost:5432/' + req.params.dbName;

    var client = new pg.Client(conString);
    client.connect(function(err) {
        if (err) {
            res.send('could not connect to postgres');
        }
        // OB: es6 template strings are great for this kind of stuff, i.e. `ALTER TABLE "${req.params.tableName}" ADD COLUMN "${req.params.numNewCol}" text`
        client.query("ALTER TABLE \"" + req.params.tableName + "\" ADD COLUMN \"" + req.params.numNewCol + "\" text", function(err, result) {

            if (err) {
                console.log(err)
                res.send('error running query');
            }
            res.set("Content-Type", 'text/javascript');
            res.send(result);
            client.end();
        });
    })
})

router.post('/:dbName/association', function(req, res, next) {
        var pg = require('pg');
        var conString = 'postgres://localhost:5432/' + req.params.dbName;
        var knex = require('knex')({
            client: 'pg',
            connection: 'postgres://localhost:5432/' + req.params.dbName,
            searchPath: 'knex,public'
        });
        // OB: dead code, burn it
        //creates the association table -- Named using DBName_assoc
        // knex.schema.createTableIfNotExists(req.params.dbName + '_assoc', function(table) {
        //         table.increments();
        //         table.string('Table1');
        //         table.string('Relationship1');
        //         table.string('Alias1');
        //         table.string('Table2');
        //         table.string('Relationship2');
        //         table.string('Alias2');
        //         table.string('Through');
        //     })
        //     //inserts association data into the association table
        //     .then(function() {
        // OB: return is not necessary here
        return knex(req.params.dbName + '_assoc').insert({
                Table1: req.body.table1.table_name,
                Alias1: req.body.alias1,
                Relationship1: req.body.type1,
                Table2: req.body.table2.table_name,
                Alias2: req.body.alias2,
                Relationship2: req.body.type2,
                Through: req.body.through
            })
            //Connects to PG to create columns
            .then(function(result) {
                var client = new pg.Client(conString);
                client.connect(function(err) {
                        if (err) {
                            console.log('DATABASE FAILED TO CONNECT')
                            res.send('database failed to connect')
                        }
                        //Player hasOne Team -- Adds teamid column using PG sets datatype to integer <-- IMPORTANT
                        if (req.body.type1 === 'hasOne') {

                            client.query("ALTER TABLE \"" + req.body.table1.table_name + "\" ADD COLUMN " + "\"" + req.body.alias1 + "\"" + " integer", function(err, result) {
                                    if (err) {
                                        console.log("ADD COLUMN FAILED", err)
                                        res.send('Error running query')
                                    }
                                })
                                //Finds newly created column ('teamid') and makes it a foreign key to Teams.id
                                //data type on both tables need to match in order for foreign key to work
                            knex.schema.table(req.body.table1.table_name, function(table) {
                                    table.foreign(req.body.alias1).references('id').inTable(req.body.table2.table_name);
                                })
                                // OB: nested .thens
                                .then(function(result) {
                                    console.log("========================", result)
                                    res.send(result);
                                })
                                .catch(function(err) {
                                    console.log(err);
                                })
                        }
                        //need to make above work in alternate direction 
                        if (req.body.type2 === 'hasOne' && req.body.type1 !== 'hasOne') {
                            client.query("ALTER TABLE \"" + req.body.table2.table_name + "\" ADD COLUMN " + req.body.alias2 + " integer", function(err, result) {
                                    if (err) {
                                        console.log("ADD COLUMN FAILED", err)
                                        res.send('Error running query')
                                    }
                                })
                                //Finds newly created column ('teamid') and makes it a foreign key to Teams.id
                                //data type on both tables need to match in order for foreign key to work
                            knex.schema.table(req.body.table2.table_name, function(table) {
                                    table.foreign(req.body.alias2).references('id').inTable(req.body.table1.table_name);
                                })
                                // OB: nested .thens
                                .then(function(result) {
                                    console.log("========================", result)
                                    res.send(result);
                                })
                                .catch(function(err) {
                                    console.log(err);
                                })
                        }
                    })
                    //creates a join table for now-- have to figure out away to make foreign key/associations align in the database 
                if (req.body.type1 === 'hasMany' && req.body.type2 === 'hasMany') {
                    console.log("--------------------------", req.body.through)
                    return knex.schema.createTable(req.body.through, function(table) {
                            table.integer(req.body.alias1).references('id').inTable(req.body.table1.table_name);
                            table.integer(req.body.alias2).references('id').inTable(req.body.table2.table_name);
                        })
                        // OB: nested .thens
                        .then(function() {
                            res.sendStatus(200);
                        })
                        .catch(next);
                }
            // })
    })
    // OB: I'm thinking you should consider cleaning this route handler up, seems to be pretty complex—break it up into smaller pieces and make those pieces functions
    .catch(next);
})

router.delete('/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })

    knex.schema.dropTable(req.params.tableName)
        .then(function(result) {
            res.status(201).send(result)
        })
        .catch(next);

})
