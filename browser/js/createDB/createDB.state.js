app.config(function ($stateProvider) {
    $stateProvider.state('createdb', {
        url: '/createdb',
        templateUrl: 'js/createdb/createdb.html',
        controller: 'CreatedbCtrl',
        resolve: {
        	loggedInUser: function(AuthService) {
        		return AuthService.getLoggedInUser();
        	}
        }
    });

});