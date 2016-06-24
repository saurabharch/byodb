'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
var Sequelize = require('sequelize');
var knex = require('knex');


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
        // if(req.body.type[key] === 'text') table.text(req.body.column[key]);
        // if(req.body.type[key] === 'float') table.float(req.body.column[key]);
        // if(req.body.type[key] === 'boolean') table.boolean(req.body.column[key]);

        table[req.body.type[key]](req.body.column[key])
      }
      table.timestamps();
    }).then(function() {
        res.sendStatus(200);
    })
    .catch(next);


})
