app.controller('QueryTableCtrl', function ($scope, TableFactory, $stateParams) {

    $scope.qFilter = function(referenceString, val){
        if(!referenceString) return true;
        else {
            for(var prop in val){
                var cellVal = val[prop].toString().toLowerCase();
                var searchVal = referenceString.toString().toLowerCase();
                console.log(cellVal, searchVal, cellVal.indexOf(searchVal) !== -1)
                if(cellVal.indexOf(searchVal) !== -1) return true;
            }
        }
        return false;
    }

})