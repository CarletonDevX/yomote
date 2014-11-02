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
		console.log(this);
	});
	$('.vote').click(function () {
  	$(this).toggleClass('on');
});
});
