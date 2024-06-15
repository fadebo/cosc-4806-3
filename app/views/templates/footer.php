<footer class="footer">    
    <div class="row">
        <div class="col-lg-12">
            <p>Copyright &copy; <?php echo date('Y'); ?> </p>
        </div>
    </div>
</footer>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>
<script>
    // JavaScript for countdown timer
    document.addEventListener('DOMContentLoaded', function() {
        var remainingTime = <?php echo $remainingTime; ?>;
        var countdownElement = document.getElementById('countdown');
        if (countdownElement && remainingTime > 0) {
            var interval = setInterval(function() {
                remainingTime--;
                countdownElement.textContent = remainingTime;
                if (remainingTime <= 0) {
                    clearInterval(interval);
                    window.location.reload(); // Reload the page when countdown ends
                }
            }, 1000);
        }
    });
</script>
<style>
    #countdown {
        font-weight: bold;
        color: red;
    }
</style>
</body>
</html>