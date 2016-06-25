app.controller('HomeCtrl', function ($scope, allDbs, loggedInUser) {
	
	if(!loggedInUser) $state.go('landingPage');

	$scope.allDbs = allDbs;
});
