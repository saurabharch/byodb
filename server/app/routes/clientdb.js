'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
var Sequelize = require('sequelize');
var knex = require('knex');
var pg = require('pg');


module.exports = router;

router.post('/', function(req, res, next) {
    var knex = require('knex')({
      client: 'pg',
      connection: 'postgres://localhost:5432/'+ req.body.dbName,
      searchPath: 'knex,public'
    });

    knex.schema.createTable(req.body.name, function (table) {
      table.increments();
      for(var key in req.body.column) {
        if(req.body.type[key] === 'text') table.text(req.body.column[key]);
        if(req.body.type[key] === 'float') table.float(req.body.column[key]);
        if(req.body.type[key] === 'boolean') table.boolean(req.body.column[key]);
      }
      table.timestamps();
    }).then(function() {
        res.sendStatus(200);
    })
    .catch(next);


})


router.get('/:dbName', function(req, res){
   var pg = require('pg'); 

    var conString = 'postgres://localhost:5432/' + req.params.dbName;

    var client = new pg.Client(conString);
    client.connect(function(err) {
      if(err) {
        res.send('could not connect to postgres');
      }
      client.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public'", function(err, result) {
        if(err) {
         res.send('error running query'); 
        }
        res.set("Content-Type", 'text/javascript'); // i added this to avoid the "Resource interpreted as Script but transferred with MIME type text/html" message
        res.send(result);
                      client.end();
      });
    }); 

});



router.get('/:dbName/:tableName', function(req, res, next){
  console.log('HERE!!!!')
  res.sendStatus(200)
})













