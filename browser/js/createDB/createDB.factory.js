app.factory('CreateDBFactory', function ($http) {

	var CreateDBFactory = {};

	function resToData(res) {
        return res.data;
    }

    CreateDBFactory.createDB = function(dbName){
    	return $http.post('/api/masterdb', dbName)
    	.then(resToData)
    }

	return CreateDBFactory; 
})