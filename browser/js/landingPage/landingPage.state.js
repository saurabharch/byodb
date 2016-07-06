app.config(function ($stateProvider) {
    $stateProvider.state('landingPage', {
        url: '/',
        templateUrl: 'js/landingPage/landingPage.html',
        controller: 'LandingPageCtrl'
        }
    );

});