app.factory('TableFactory', function ($http) {

	var TableFactory = {};

	function resToData(res) {
        return res.data;
    }

    TableFactory.getAllTables = function(dbName){
    	return $http.get('/api/clientdb/' + dbName)
    	.then(resToData)
    }

    TableFactory.getSingleTable = function(dbName, tableName){
        return $http.get('/api/clientdb/' + dbName + '/' + tableName)
        .then(resToData)
    }

    TableFactory.getDbName = function(dbName){
        return $http.get('/api/masterdb/' + dbName)
        .then(resToData)
    }

    TableFactory.filter = function(dbName, tableName, data) {
        return $http.put('/api/clientdb/' + dbName + '/' + tableName + '/filter', data)
    }

    TableFactory.removeRow = function(dbName, tableName, rowId){
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/' + rowId)
        .then(resToData)
    }

    TableFactory.updateBackend = function(dbName, tableName, data) {
        return $http.put('api/clientdb/' + dbName + '/' + tableName, data)
        .then(resToData);
    }

    TableFactory.addRow = function(dbName, tableName, rowNumber) {
        return $http.post('api/clientdb/addrow/' + dbName + '/' + tableName, {rowNumber: rowNumber})
        .then(resToData);
    }

    TableFactory.addColumn = function(dbName, tableName, numNewCol){
        return $http.post('api/clientdb/addcolumn/' + dbName + '/' + tableName + '/' + numNewCol)
    }

    TableFactory.makeAssociations = function(association, dbName) {
        console.log(association)
        return $http.post('/api/clientdb/' + dbName + '/association', association)
        .then(resToData);
    }

	return TableFactory; 
})