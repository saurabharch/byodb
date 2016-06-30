'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
var Sequelize = require('sequelize');
var knex = require('knex');
var pg = require('pg');


module.exports = router;



//get all the information from the association table
router.get('/allassociations/:dbName', function(req, res, next) {
  var knex = require('knex')({
      client: 'pg',
      connection: 'postgres://localhost:5432/' + req.params.dbName,
      searchPath: 'knex,public'
  })

  knex.select().table(req.params.dbName + '_assoc')
    .then(function(result) {
        console.log(result);
        res.send(result);
    })
})

//get information from the association table for a single table
router.get('/associationtable/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })

    knex(req.params.dbName + '_assoc').where(function() {
        this.where('Table1', req.params.tableName).orWhere('Table2', req.params.tableName)
    })
    .then(function(result) {
        console.log(result);
        res.send(result);
    })
})

// delete a db
router.delete('/:dbn', function(req, res) {
    var pg = require('pg');

    var conString = 'postgres://localhost:5432/masterDB';

    var client = new pg.Client(conString);
    client.connect(function(err) {
        if (err) {
            console.log(err)
            res.send('could not connect to postgres');
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
              res.set("Content-Type", 'text/javascript'); //avoid the "Resource interpreted as Script but transferred with MIME type text/html" message
              res.send(result);
              client.end();
            });
    });

});

router.post('/', function(req, res, next) {
    if (!req.user) res.sendStatus(404);

    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.body.dbName,
        searchPath: 'knex,public'
    });

    knex.schema.createTable(req.body.name, function(table) {
            table.increments();
            for (var key in req.body.column) {
                table[req.body.type[key]](req.body.column[key])
            }
            table.timestamps();
        }).then(function() {
            return knex(req.body.name).insert([
                    {id: 1},
                ]);
        })
        .catch(next);
})

//route to get all tables from a db
// DO WE NEED TO INCLUDE SOMETHING TO HANDLE INJECTION ATTACK?
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
            res.set("Content-Type", 'text/javascript'); //avoid the "Resource interpreted as Script but transferred with MIME type text/html" message
            res.send(result);
            client.end();
        });
    });

});

//route to get a single table from a db
// DO NEED TO COME UP WITH A WAY TO REMOVE SPACES FROM THE TABLE NAME WHEN IT GETS SAVED?
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
router.put('/:dbName/:tableName/filter', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })
    knex(req.params.tableName).where(req.body.column, req.body.comparator, req.body.value)
        .then(function(result) {
            console.log(result);
            res.send(result)
        })
        .catch(next);
})

//route to update data in a table (columns and rows)
router.put('/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    })
    var promises = [];
    req.body.rows.forEach(function(row) {
        var promise = knex(req.params.tableName)
            .where('id', '=', row.id)
            .update(row)

        promises.push(promise)
    })
    Promise.all(promises)
        .then(function(result) {
            var promises2 = [];
            req.body.columns.forEach(function(column) {
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
    .then(function(){
        knex.select().from(req.params.tableName)
            .then(function(foundTable) {
                res.send(foundTable)
            })
    })
    .catch(next);
})

// delete column in table
router.delete('/:dbName/:tableName/column/:columnName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });
    knex.schema.table(req.params.tableName, function (table) {
      table.dropColumn(req.params.columnName)
    })
    .then(function(res){
        return knex.select().from(req.params.tableName)
    })
    .then(function(foundTable) {
        res.send(foundTable)
    })
    .catch(next);
})

router.post('/addrow/:dbName/:tableName', function(req, res, next) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + req.params.dbName,
        searchPath: 'knex,public'
    });
    knex(req.params.tableName).insert({id: req.body.rowNumber})
    .then(function(){
        knex.select().from(req.params.tableName)
            .then(function(foundTable) {
                console.log(foundTable)
                res.send(foundTable)
            })
    })
    .catch(next);
})

router.post('/addcolumn/:dbName/:tableName/:numNewCol', function(req, res, next) {
    var pg = require('pg');

    var conString = 'postgres://localhost:5432/' + req.params.dbName;

    var client = new pg.Client(conString);
    client.connect(function(err) {
        if (err) {
            res.send('could not connect to postgres');
        }
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
    //creates the association table -- Named using DBName_assoc
    knex.schema.createTableIfNotExists(req.params.dbName+'_assoc', function(table) {
            table.increments();
            table.string('Table1');
            table.string('Relationship1');
            table.string('Alias1');
            table.string('Table2');
            table.string('Relationship2');
            table.string('Alias2');
            table.string('Through');
        })
        //inserts association data into the association table
        .then(function() {
            return knex(req.params.dbName+'_assoc').insert({
              Table1: req.body.table1.table_name,
              Alias1: req.body.alias1,
              Relationship1: req.body.type1,
              Table2: req.body.table2.table_name,
              Alias2: req.body.alias2,
              Relationship2: req.body.type2,
              Through: req.body.through
            })
        //Connects to PG to create columns
        .then(function(result){
            var client = new pg.Client(conString);
            client.connect(function(err){
              if(err){
                console.log('DATABASE FAILED TO CONNECT')
                res.send('database failed to connect')
              }
              //Player hasOne Team -- Adds teamid column using PG sets datatype to integer <-- IMPORTANT
              if(req.body.type1 === 'hasOne'){

                client.query("ALTER TABLE \"" + req.body.table1.table_name + "\" ADD COLUMN " + "\"" + req.body.alias1 + "\"" + " integer", function(err, result){
                  if(err){
                    console.log("ADD COLUMN FAILED", err)
                    res.send('Error running query')
                  }
                })
                //Finds newly created column ('teamid') and makes it a foreign key to Teams.id
                //data type on both tables need to match in order for foreign key to work
                knex.schema.table(req.body.table1.table_name, function(table){
                  table.foreign(req.body.alias1).references('id').inTable(req.body.table2.table_name);
                })
                .then(function(result){
                  console.log("========================", result)
                  res.send(result);
                })
                .catch(function(err){
                  console.log(err);
                })
              }
              //need to make above work in alternate direction 
              if(req.body.type2 === 'hasOne' && req.body.type1 !== 'hasOne'){
                client.query("ALTER TABLE \"" + req.body.table2.table_name + "\" ADD COLUMN " + req.body.alias2 + " integer", function(err, result){
                  if(err){
                    console.log("ADD COLUMN FAILED", err)
                    res.send('Error running query')
                  }
                })
                //Finds newly created column ('teamid') and makes it a foreign key to Teams.id
                //data type on both tables need to match in order for foreign key to work
                knex.schema.table(req.body.table2.table_name, function(table){
                  table.foreign(req.body.alias2).references('id').inTable(req.body.table1.table_name);
                })
                .then(function(result){
                  console.log("========================", result)
                  res.send(result);
                })
                .catch(function(err){
                  console.log(err);
                })
              }
            })
            //creates a join table for now-- have to figure out away to make foreign key/associations align in the database 
            if(req.body.type1 === 'hasMany' && req.body.type2 === 'hasMany'){
              console.log("--------------------------", req.body.through)
              return knex.schema.createTable(req.body.through, function(table) {
                      table.integer(req.body.alias1).references('id').inTable(req.body.table1.table_name);
                      table.integer(req.body.alias2).references('id').inTable(req.body.table2.table_name);
                  })
              .then(function() {
                      res.sendStatus(200);
                  })
              .catch(next);
            }
          })
        })
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





























