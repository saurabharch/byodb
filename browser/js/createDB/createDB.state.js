app.config(function ($stateProvider) {
    $stateProvider.state('createdb', {
        url: '/createdb',
        templateUrl: 'js/createDB/createDB.html',
        controller: 'CreatedbCtrl',
        resolve: {
        	loggedInUser: function(AuthService) {
        		return AuthService.getLoggedInUser();
        	}
        }
    });

});
