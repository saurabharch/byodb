app.factory('HomeFactory', function ($http) {

	var HomeFactory = {};

	function resToData(res) {
        return res.data;
    }

    HomeFactory.getAllDbs = function(){
    	return $http.get('/api/masterdb')
    	.then(resToData)
    }

    HomeFactory.deleteDB = function(name){
    	return $http.delete('/api/masterdb/' + name)
    	.then(resToData)
    }

	return HomeFactory; 
})