$(document).ready(function () {
	var prev = null;
	$('#main .service').each(function(){
		var classes = ['red', 'green', 'yellow', 'purple', 'darkblue', 'turquoise','emerald','blue','belize'];
		var i;
		while(true){
			i = Math.floor(Math.random() * classes.length);
			if (i != prev) { break };
		}
		prev=i;
		$(this).addClass(classes[i]);
	});

	$('.about').click(function(){
		$( "#content" ).load( "/static/about.html", function() {
			console.log("loaded script successfully");
		} );
		return false;
	});

	$('.create').click(function(){
		$( "#content" ).load( "/create", function() {
			console.log("loaded script successfully");
		} );
		return false;
	})
});
