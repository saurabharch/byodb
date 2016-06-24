'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
// var pg = require('pg');
var Sequelize = require('sequelize');
var knex = require('knex');


module.exports = router;

router.post('/', function(req, res, next) {
    console.log(req.body);
    var knex = require('knex')({
      client: 'pg',
      connection: 'postgres://localhost:5432/'+ req.body.dbName,
      searchPath: 'knex,public'
    });

    knex.schema.createTable(req.body.name, function (table) {
      table.increments();
      // table.string(req.body.name);
      table.timestamps();
    }).then(function() {
        res.sendStatus(200);
    })
    .catch(next);


})
