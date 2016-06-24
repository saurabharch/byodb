'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
var pg = require('pg');
var Sequelize = require('sequelize');


module.exports = router;

router.post('/', function(req, res, next) {
    console.log(req.body);
    Database.create(req.body)
    .then(function(createdDB) {
        Database.makeClientDatabase(createdDB);
        return createdDB
    })
    .then(function(createdDB) {
        res.send(createdDB);
    })
    .catch(next);

    // Database.create(req.body)
    // .then(function(createdDB) {
    //     var dbName = createdDB.dbName;
    //     var connectionString = 'postgres://localhost:5432/masterDB';

    //     var client = new pg.Client(connectionString);
    //     client.connect();
    //     var query = client.query('CREATE DATABASE ' + dbName);
    //     query.on('end', function() { client.end(); });
    //     res.send(createdDB);
    // })
    // .catch(next);
})
