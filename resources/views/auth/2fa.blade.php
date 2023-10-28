@extends('auth.layout')

@section('content')
    <div class="flex flex-col items-center justify-center min-h-screen bg-cover bg-center bg-gray-100">
        <div class="w-full max-w-md">
            <div class="bg-white rounded-lg shadow-lg p-8">
            <div class="flex justify-center">
                <img class="h-36 w-36" src="https://d1csarkz8obe9u.cloudfront.net/posterpreviews/company-logo-design-template-e089327a5c476ce5c70c74f7359c5898_screen.jpg?ts=1672291305" alt="Logo">
            </div>
            <form class="mt-8" method="POST" action="{{ route('submit_2fa') }}">
                @csrf
                <div>
                    <label class="block text-gray-700 font-bold mb-2" for="code">
                        Code
                    </label>
                    <input name="code" type="number" class="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="code" type="text" placeholder="Code">
                    </div>
                    <div class="mt-8">

                    {{-- show proceed button after press resent otp and wait until 1 minute and show timer  --}}

                        <div class="text-sm text-gray-700">
                            {{ __('Please confirm access to your account by entering the authentication code provided by your authenticator application.') }}
                        </div>

                        {{-- show the button to continue --}}
                        <div class="flex items-center justify-between mt-4">
                            {{-- <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">
                                Proceed with 2FA
                            </button> --}}




                            <div class="text-sm text-gray-700 w-full">
                                <span id="timer"></span>

                                <script>

                                    // keep the funtion in loop
                                    document.getElementById("timer").innerHTML = '';


                                    function loop_event () {
                                        var timeleft = 5;
                                        var downloadTimer = setInterval(function(){
                                        if(timeleft <= 0){
                                            clearInterval(downloadTimer);

                                            //show the button to resent otp with OnClick event
                                            document.getElementById("timer").innerHTML = '<button type="button" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button" onclick="resend_otp()">Resent OTP</button>';

                                        } else {
                                            var timeL = timeleft + " seconds remaining";

                                            //now add the remaining time to the button
                                            document.getElementById("timer").innerHTML = '<button type="submit" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">Proceed with 2FA ('+timeL+')</button>';
                                        }
                                        timeleft -= 1;
                                        }, 1000);
                                    }


                                    // call the function
                                    loop_event();

                                    // function to resent otp
                                    function resend_otp() {
                                        //turn above into ajax
                                        $.ajax({
                                            url: "{{ route('verification.resend') }}",
                                            type: "POST",
                                            // pass the cookies along
                                            xhrFields: {
                                                withCredentials: true
                                            },
                                            data: {
                                                _token: '{{ csrf_token() }}'
                                            },
                                            beforeSend: function() {
                                                console.log('loading');
                                                document.getElementById("timer").innerHTML = '';
                                            },
                                            success: function(response) {
                                                //call the function again after 2 seconds
                                                setTimeout(function() {
                                                    loop_event();
                                                }, 1000);
                                            },
                                            error: function(xhr) {

                                                //if 401 then reload the page to redirect to login
                                                if (xhr.status == 401) {
                                                    location.reload();
                                                }

                                                //show the button to resent otp with OnClick event
                                                setTimeout(function() {
                                                    document.getElementById("timer").innerHTML = '<button type="button" class="w-full bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button" onclick="resend_otp()">Resent OTP</button>';
                                                }, 1000);
                                            }
                                        });

                                    }
                                </script>


                            </div>
                        </div>





                    {{-- <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" type="button">
                        Proceed with 2FA
                    </button> --}}
                </div>
            </form>

            </div>
        </div>
    </div>
@endsection
