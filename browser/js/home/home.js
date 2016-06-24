// app.config(function ($stateProvider) {
//     $stateProvider.state('home', {
//         url: '/',
//         templateUrl: 'js/home/home.html'
//     });
// });

app.config(function ($stateProvider) {
    $stateProvider.state('Home', {
        url: '/home',
        templateUrl: 'js/Home/Home.html',
        controller: 'HomeCtrl'
        }
    );

});

app.factory('HomeFactory', function ($http) {

	var HomeFactory = {};

	function resToData(res) {
        return res.data;
    }
	return HomeFactory; 
})

app.controller('HomeCtrl', function ($scope, HomeFactory, $state, $stateParams) {

});
