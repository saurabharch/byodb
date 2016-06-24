app.config(function ($stateProvider) {
    $stateProvider.state('Home', {
        url: '/home',
        templateUrl: 'js/Home/Home.html',
        controller: 'HomeCtrl',
        resolve : {
            loggedInUser: function (AuthService) {
                return AuthService.getLoggedInUser();
            }
        }
    });

});

app.factory('HomeFactory', function ($http) {

	var HomeFactory = {};

	function resToData(res) {
        return res.data;
    }
	return HomeFactory; 
})

app.controller('HomeCtrl', function ($scope, HomeFactory, $state, $stateParams, loggedInUser) {

    if(!loggedInUser) $state.go('landingPage');

});
