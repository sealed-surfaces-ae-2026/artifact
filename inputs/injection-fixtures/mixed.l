(+ (* 6 7) 5)
(car (cdr '(10 20 30)))
(define (factorial n)
  (if (= n 0)
      1
      (* n (factorial (- n 1)))))
(factorial 6)
(if (> 3 2) 'yes 'no)
