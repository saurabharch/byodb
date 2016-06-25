app.factory('HomeFactory', function ($http) {

	var HomeFactory = {};

	function resToData(res) {
        return res.data;
    }

    HomeFactory.getAllDbs = function(){
    	return $http.get('/api/masterdb')
    	.then(resToData)
    }

	return HomeFactory; 
})