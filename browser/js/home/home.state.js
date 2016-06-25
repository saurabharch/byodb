app.config(function ($stateProvider) {
    $stateProvider.state('Home', {
        url: '/home',
        templateUrl: 'js/Home/Home.html',
        controller: 'HomeCtrl',
        resolve: {
        	allDbs: function(HomeFactory){
        		return HomeFactory.getAllDbs();
        	}
        }
    });
});