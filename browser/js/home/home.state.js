app.config(function ($stateProvider) {
    $stateProvider.state('Home', {
        url: '/home',
        templateUrl: 'js/home/home.html',
        controller: 'HomeCtrl',
        resolve: {
        	allDbs: function(HomeFactory){
        		return HomeFactory.getAllDbs();
        	},
            loggedInUser: function (AuthService) {
                return AuthService.getLoggedInUser();
            }
        }
    });
});
