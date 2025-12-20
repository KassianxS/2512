# dz25.12

## bin2.exe
<img width="939" height="355" alt="Снимок экрана 2025-12-19 183225" src="https://github.com/user-attachments/assets/5fb8c29b-76ed-4701-9d9b-83654cffb9e9" />


достаем ida, достаем код

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  bool v5; // zf
  const char *v6; // rcx
  int v8; // [rsp+20h] [rbp-28h]
  int v9; // [rsp+24h] [rbp-24h]
  int v10; // [rsp+28h] [rbp-20h]
  int v11; // [rsp+2Ch] [rbp-1Ch]
  int v12; // [rsp+30h] [rbp-18h]
  int v13; // [rsp+34h] [rbp-14h]

   puts("Input password: ");
  sub_140001084("%s");
  v3 = ((v8 ^ v9) == 440483881) + 1;
  if ( (v10 ^ v11) != 1778845442 )
    v3 = (v8 ^ v9) == 440483881;
  v4 = v3 + 1;
  if ( (v12 ^ v13) != 1463812392 )
    v4 = v3;
  v5 = v4 == 3;
  v6 = "YES";
  if ( !v5 )
    v6 = "NO";
  puts(v6);
  return 0;
}

```
у нас просят ввести пароль

замечаем в коде проверку на равенство XOR соседних 4-байтовых блоков конкретным значениям
Если все три равенства выполняются (т.е. `v4 == 3`), программа выводит "YES", иначе "NO"
когда мы подбираем пароль, чтобы XOR двух соседних четверок дал нужное число, надо сначала посчитать, а потом уже перевернуть каждую четверку.

есть начальная строка qw3r, она подразделяется на четверки, их шесть, все эти четверки отзеркалены, каждые 4 символа отзеркалены. Я просто на рандом вводил 4 символа. Первая четверка, я ее на рандом ввожу, ксорю ее, 44, 48 и так далее. Получаю вторую четверку, потом ввожу третью рандомную четверку, ксорю ее 17 и так далее, получаю четвертую четверку. И с последней четверкой делаю то же самое

## bin3.exe

<img width="921" height="325" alt="Снимок экрана 2025-12-19 185745" src="https://github.com/user-attachments/assets/f3bfb87d-a351-476e-8105-f44a7f3daaeb" />


достаем код
main
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Destination[128]; // [esp+0h] [ebp-80h] BYREF

  if ( argc >= 2 )
  {
    if ( (unsigned int)((int (__cdecl *)(const char *))((char *)&etext + 1))(argv[1]) <= 0x80 )
    {
      strncpy(Destination, argv[1], 0x80u);
      swaper(Destination, 10);
      swaper(Destination, 9);
      swaper(Destination, 8);
      swaper(Destination, 7);
      swaper(Destination, 6);
      swaper(Destination, 5);
      swaper(Destination, 4);
      swaper(Destination, 3);
      swaper(Destination, 2);
      printf("%s\n", Destination);
      return 0;
    }
    else
    {
      printf("String is too long\n");
      return 1;
    }
  }
  else
  {
    printf("Give me a string\n");
    return 1;
  }
}
```
программа принимает на ввод строку, если был пустой ввод, выдаст `Give me a string`, если длинее 128 символов, то выводит `String is too long` если строка попадает в радиус от 1 до 128 символов, то она копируется в буфер назначения `Destination`, также у нас есть `swaper`

```c
int __cdecl swaper(int a1, int a2)
{
  int result; // eax
  unsigned int i; // [esp+0h] [ebp-Ch]
  char v4; // [esp+7h] [ebp-5h]
  int v5; // [esp+8h] [ebp-4h]

  v5 = ((int (__cdecl *)(int))((char *)&etext + 1))(a1);
  for ( i = 0; ; i += a2 )
  {
    result = v5 - a2;
    if ( i >= v5 - a2 )
      break;
    v4 = *(_BYTE *)(i + a1);
    *(_BYTE *)(i + a1) = *(_BYTE *)(a2 + i - 1 + a1);
    *(_BYTE *)(a2 + i - 1 + a1) = v4;
  }
  return result;
}
```
свапер вызывается 9 раз, и она будет менять местами наш `Destination`, функция `swaper` берет строку и число (шаг).
Она проходит по строке, начиная с начала, каждый раз прыгая вперед на шаг символов.
На каждом таком "прыжке", она меняет местами текущий символ (по индексу i) с символом, который находится на шаг - 1 позицию дальше от него (по индексу i + шаг - 1).
Если при "прыжке" на шаг позиций мы выходим за конец строки, обмены прекращаются.

## bin4.exe

<img width="933" height="422" alt="Снимок экрана 2025-12-19 190602" src="https://github.com/user-attachments/assets/7c7080dd-f3d9-4d38-a370-59a7fcac2af7" />

ida, достаем код
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char flag_buff[25]; // [rsp+20h] [rbp-60h] BYREF
  int b; // [rsp+48h] [rbp-38h] BYREF
  int a; // [rsp+4Ch] [rbp-34h] BYREF
  char message[38]; // [rsp+50h] [rbp-30h] BYREF
  int i; // [rsp+7Ch] [rbp-4h]

  _main(argc, argv, envp);
  strcpy(message, "{O3IZ_5VFI3Y_7PDDJ0IA_7XI_SI1CY_Q4PL}");
  flag_buff[0] = 29;
  flag_buff[1] = 37;
  flag_buff[2] = 87;
  flag_buff[3] = 39;
  flag_buff[4] = 60;
  flag_buff[5] = 27;
  flag_buff[6] = 7;
  flag_buff[7] = 50;
  flag_buff[8] = 27;
  flag_buff[9] = 36;
  flag_buff[10] = 85;
  flag_buff[11] = 96;
  flag_buff[12] = 63;
  flag_buff[13] = 78;
  flag_buff[14] = 113;
  flag_buff[15] = 38;
  flag_buff[16] = 45;
  flag_buff[17] = 7;
  flag_buff[18] = 8;
  flag_buff[19] = 63;
  flag_buff[20] = 42;
  flag_buff[21] = 19;
  qmemcpy(&flag_buff[22], "\v-", 2);
  puts("[*] Enter the first number: ");
  scanf("%d", &a);
  puts("[*] Enter the second number: ");
  scanf("%d", &b);
  decrypt(message, a, b);
  for ( i = 0; i < strlen(flag_buff); ++i )
    flag_buff[i] ^= message[i % strlen(message)] + 1;
  puts(flag_buff);
  system("Pause");
  return 0;
}
```
данная строка копируется в str, программа просит ввести 2 числа. Затем вызывается функция decrypt, которая шифрует только заглавные буквы, остальные оставляя неизменными. Только заглавные буквы строки преобразуются, затем XORятся с элементами Buffer, предварительно увеличив каждый символ строки на 1.

Пример: символы { и 3 после XOR дают a и c, что указывает на начало флага — arctf.
Чтобы найти r: исходный символ O перед XOR становится V через decrypt.
Уравнение:

86 = j * v4 % 26 + 65  
где j = 79 - 65.
Получаем j * v4 % 26 = 21.
Методом подбора находим v4 = 21, затем второе число 15.

## bin5.exe

<img width="987" height="682" alt="Снимок экрана 2025-12-19 193039" src="https://github.com/user-attachments/assets/a3a059e6-bfe2-473e-b721-3983df1a79d3" />

самый трудный бинарник...

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char q5[100]; // [rsp+20h] [rbp-80h] BYREF
  int q4; // [rsp+8Ch] [rbp-14h] BYREF
  int q3; // [rsp+90h] [rbp-10h] BYREF
  int q2; // [rsp+94h] [rbp-Ch] BYREF
  int q1; // [rsp+98h] [rbp-8h] BYREF
  int cnt; // [rsp+9Ch] [rbp-4h]

  _main(argc, argv, envp);
  setlocale(0, "Rus");
  puts(&Buffer);
  scanf("%d", &q1);
  if ( q1 == 2500 )
  {
    ++cnt;
    puts(&byte_404032);
  }
  else
  {
    puts(&byte_404039);
  }
  puts(&byte_404048);
  scanf("%d", &q2);
  if ( q2 == 1828 )
  {
    ++cnt;
    puts(&byte_404032);
  }
  else
  {
    puts(&byte_404039);
  }
  puts(&byte_404088);
  scanf("%d", &q3);
  if ( q3 == 360 )
  {
    ++cnt;
    puts(&byte_404032);
  }
  else
  {
    puts(&byte_404039);
  }
  puts(&byte_4040B8);
  scanf("%d", &q4);
  if ( q4 == 9 )
  {
    ++cnt;
    puts(&byte_404032);
  }
  else
  {
    puts(&byte_404039);
  }
  puts(&byte_404100);
  scanf("%s", q5);
  if ( !strcmp(q5, "CaptureTheFlag") )
  {
    ++cnt;
    puts(&byte_404032);
  }
  else
  {
    puts(&byte_404039);
  }
  if ( cnt == 5 )
    puts("arctf{a_l0t_o7_q4est1ons}");
  else
    puts(&byte_404170);
  system("Pause");
  return 0;
}
```
в коде видно флаг и ответы

## bin6.exe

Программа генерирует несколько случайных чисел. От пользователя требуется ввести произведение этих чисел.
Дешифровка строки (при верном ответе): Если введенное произведение чисел верно, запускается дешифрующий процесс:
Берётся закодированная строка: `dwfqc~0qwdkb6Zv2w4kbx`.
Каждый символ этой строки XOR-ится с числом 5.
Исходный символ заменяется полученным результатом.
После всех операций дешифровки получается финальная строка: `arctf{5trang3_s7r1ng}`.

## bin7.exe



```c
int __cdecl sub_401000(int (__cdecl *a1)(int, _DWORD), int a2, int a3, _DWORD *a4)
{
  int v4; // eax

  if ( !a3 )
    return a2;
  v4 = a1(a2, *a4);
  return sub_401000(a1, v4, a3 - 1, a4 + 1);
}
```

Чтобы программа вывела "Correct!", нужно пройти две проверки:

1. Проверка на XOR-сумму:
Мы берем 0 и последовательно XOR-им его с каждым из 10 введенных чисел.
Конечный результат должен быть равен 0.
Для этого введенные числа должны образовывать пары. Например, если ввести {1,1,2,2,3,3,4,4,5,5}, то:
0 XOR 1 = 1
1 XOR 1 = 0
0 XOR 2 = 2
2 XOR 2 = 0
...и так далее, пока 0 XOR 5 = 5, 5 XOR 5 = 0.
Итоговый результат будет 0.

2. Проверка на логическое И (AND):
Мы берем 1 и последовательно применяем к нему логическую операцию И (AND) с каждым из 10 введенных чисел.
Цель: Конечный результат должен быть не равен 0.
Решение: Если все введенные числа (например, {1,1,2,2,3,3,4,4,5,5}) отличны от 0, то результат каждого AND будет 1 (true).
1 AND 1 = 1
1 AND 1 = 1
AND 2 = 1 (т.к. 2 не 0)
и так далее, до 1 AND 5 = 1.
Итоговый результат будет 1, что не равно 0.
Для получения "Correct!" необходимо ввести 10 чисел, которые:
Являются ненулевыми.
Встречаются парами, чтобы их XOR-сумма обнулялась.
Например, строка {1,1,2,2,3,3,4,4,5,5} подходит идеально



## bin8.exe

<img width="865" height="368" alt="Снимок экрана 2025-12-19 223043" src="https://github.com/user-attachments/assets/7cc011a6-a2f2-4da0-b096-993df5f198cd" />

ida, код

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Arglist[4]; // [esp+0h] [ebp-8h] BYREF

  sub_401020("Input password (number): >", Arglist[0]);
  sub_401050("%d", (char)Arglist);
  if ( (5 * *(_DWORD *)Arglist * *(_DWORD *)Arglist % 256 - 34 * *(_DWORD *)Arglist + 24) % 256 )
    sub_401020("Go out of here!\n", Arglist[0]);
  else
    sub_401020("You are welcome! Now you can use this app.\n", Arglist[0]);
  system("pause");
  return 0;
}
```

Как работает проверка пароля: программа просит пользователя ввести одно число (пароль). Это число, назовем его a, используется в специальном уравнении.
Если результат этого уравнения равен 0, программа принимает пароль как верный. В противном случае — пароль неверный.

Математическая проверка:

Уравнение для проверки пароля - `(5  a^2 - 34  a + 24) % 256 = 0`
Найденный верный пароль - Решая это уравнение, мы получаем, что a = 6 является верным паролем.

## bin10.exe

<img width="931" height="544" alt="Снимок экрана 2025-12-19 225208" src="https://github.com/user-attachments/assets/e98bbfae-6b98-4417-8a5d-5563524a4a87" />

достаем код
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // ecx
  int v5; // edx
  int v7; // [esp+8h] [ebp-8h] BYREF
  int v8; // [esp+Ch] [ebp-4h] BYREF

  printf("Input your age: >");
  scanf("%d", &v7);
  if ( v7 >= 14 )
  {
    if ( v7 < 100 )
    {
      printf("Input current year: >");
      scanf("%d", &v8);
      v3 = v8;
      if ( v8 >= 2017 )
      {
        if ( v8 <= 2200 )
        {
          v4 = v7;
          if ( v7 )
          {
            do
            {
              v5 = v3 % v4;
              v3 = v4;
              v4 = v5;
            }
            while ( v5 );
            v7 = 0;
            v8 = v3;
          }
          if ( v3 == 7 )
            printf("You are welcome! Now you can use this app.\n");
          else
            printf("Go out of here!\n");
        }
        else
        {
          printf("Too late!\n");
        }
      }
      else
      {
        printf("Too early!\n");
      }
    }
    else
    {
      printf("Too old!\n");
    }
  }
  else
  {
    printf("Too young!\n");
  }
  system("pause");
  return 0;
}
```

программа спрашивает возраст и проверяет, что он должен быть от 14 до 99 (включительно 14, но не 100). Если не так, сказать об ошибке.
также спрашивает год, проверяет: он должен быть от 2017 до 2200 (включительно). Если не так, сказать об ошибке.

Программа находит НОД двух чисел: v3 (год) и v4 (возраст), используя алгоритм Евклида.
Последняя проверка сравнивает полученный НОД с 7.
Таким образом, НОД введённых возраста и года должен быть равен 7.

Пример подходящих значений: 14 (возраст) и 2023 (год), так как
НОД(14, 2023) = 7.

Другие подходящие пары можно получить, увеличивая оба числа на 7 с учётом ограничений программы.

## bin11.exe

<img width="867" height="350" alt="Снимок экрана 2025-12-19 230208" src="https://github.com/user-attachments/assets/b6aa6d35-7666-4911-b1fc-372ed2802691" />

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char Arglist[256]; // [esp+0h] [ebp-13Ch] BYREF
  char Destination[7]; // [esp+100h] [ebp-3Ch] BYREF
  char v7[33]; // [esp+107h] [ebp-35h] BYREF
  char Source[16]; // [esp+128h] [ebp-14h] BYREF

  strcpy(Source, "simple_answer");
  sub_401020("Input valid serial key: >", Arglist[0]);
  sub_401050("%s", (char)Arglist);
  strncpy(Destination, &Source[7], 6u);
  Destination[6] = 95;
  strncpy(v7, Source, 6u);
  v7[6] = 0;
  v3 = strcmp(Arglist, Destination);
  if ( v3 )
    v3 = v3 < 0 ? -1 : 1;
  if ( v3 )
    sub_401020("Go out of here!\n", Arglist[0]);
  else
    sub_401020("You are welcome! Now you can use this app.\n", Arglist[0]);
  system("pause");
  return 0;
}
```
Чтобы получить сообщение `You are welcome!`, введённая строка `Arglist` должна полностью совпадать со строкой Destination после всех преобразований. Тогда v3 станет равным 0, условие в if не выполнится, и программа перейдёт в блок else с приветствием.

Достаточно посмотреть в памяти, чему равна `Destination` после обработки — это и будет верный ответ.

## bin12.exe



```c
 {
    if ( byte_403000[v0] == 13 )
      break;
    v1 = (unsigned __int8)rand();
    byte_4030FF[v0] = v1;
    v2 = (unsigned __int16)v1 % 8u;
    LOBYTE(v1) = (unsigned __int16)v1 / 8u;
    BYTE1(v1) = v2;
    v3 = v1 >> 8;
    do
    {
      if ( !v3 )
        break;
      v4 = byte_403000[v0] >> 7;
      byte_403000[v0] *= 2;
      byte_403000[v0] |= v4;
      --v3;
    }
    while ( v3 );
    byte_403000[v0] = ~byte_403000[v0];
    ++v0;
  }
  while ( v0 );
}
```
В алгоритме шифрования для каждого символа используется следующий процесс генерация случайного числа для каждого символа, которое сохраняется в отдельный список (4030FF). Вычисление параметра сдвига из случайного числа вычисляется значение v3 как остаток от деления на 8 (v3 = random_number % 8).
Циклический сдвиг символа, пока v3 > 0, сохраняется самый старший бит (7-й бит) символа, символ сдвигается влево на 1 бит, сохраненный старший бит помещается в младшую позицию (0-й бит) значение v3 уменьшается на 1
Этот процесс фактически выполняет циклический сдвиг влево на v3 бит в двоичном представлении ASCII-кода символа.
Применение отрицания
После всех сдвигов (когда v3 = 0) к символу применяется операция побитового отрицания (~). Переход к следующему символу:
Для каждого следующего символа генерируется новое случайное число, и процесс повторяется.
Итоговый формат зашифрованных данных: каждый символ хранится вместе с соответствующим случайным числом в формате:
2 шестнадцатеричные цифры зашифрованного символа
2 шестнадцатеричные цифры случайного числа


```c
def decode_secret_message(encoded_hex_string):

    message_bytes = []
    shift_control_values = []

    for i in range(0, len(encoded_hex_string), 4):
        data_hex = encoded_hex_string[i: i + 2]
        message_bytes.append(int(data_hex, 16))

        control_hex = encoded_hex_string[i + 2: i + 4]
        shift_control_values.append(int(control_hex, 16))

    processed_shift_amounts = [val % 8 for val in shift_control_values]

    final_decrypted_bytes = []
    for i in range(len(message_bytes)):
        current_byte = message_bytes[i]
        shift_amount = processed_shift_amounts[i]

        inverted_byte = current_byte ^ 0xFF

        byte_after_rotation = inverted_byte
        for i in range(shift_amount):
            # Сохраняем младший бит
            least_significant_bit = byte_after_rotation & 1
            # Сдвигаем все биты вправо на 1 позицию
            byte_after_rotation >>= 1
            # Перемещаем сохраненный младший бит в старшую позицию
            byte_after_rotation |= (least_significant_bit << 7)

        final_decrypted_bytes.append(byte_after_rotation)

    result_string = ''.join(chr(b) for b in final_decrypted_bytes)

    return result_string


encrypted_data = 'e93cd8f4e4738b3099bc907d3fda46365ee91c5dccb33492391a71e62363be2f8756cacdc243392233a1f1a8ce4ca77565af48b33596efa466ae9d48c5b98a4e99c94e8565a49342b89dc93e94423eeb22d496c33a9d8353e33b905331ebc5c3e73dc64e3df33ba2fba67b7c7b88cfc05c9'

decoded_message = decode_secret_message(encrypted_data)
print(decoded_message)
```
с помощью кода написанного на питоне, сделал расшифровку и получил `arctf{akjsdfnav18923787jjafdnanvakjkjdasjkf9823482834187}`

## bin13.exe

<img width="898" height="465" alt="Снимок экрана 2025-12-19 234704" src="https://github.com/user-attachments/assets/c8b40e80-5ebf-4cb7-a998-fe8f30f80b14" />

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-34h]
  int idx; // [esp+4h] [ebp-30h]
  char Str[42]; // [esp+Ah] [ebp-2Ah] BYREF

  if ( argc >= 3 )
  {
    strcpy(Str, "dix_gyhiiz}xdduah}puvyhn}u}pxa}tnbfh}ozbc");
    idx = get_idx(*argv[1]);
    v4 = get_idx(*argv[2]);
    if ( idx == -1 || v4 == -1 )
    {
      ((void (__cdecl *)(char *))((char *)&etext + 1))(aSorryBro);
      return 3;
    }
    else
    {
      decode(Str, idx, v4);
      ((void (__cdecl *)(char *))((char *)&etext + 1))(Str);
      return 0;
    }
  }
  else
  {
    ((void (__cdecl *)(char *))((char *)&etext + 1))(aWhaaaaat);
    return 2;
  }
}
```

Программа анализирует аргументы командной строки, проверяет количество аргументов.
Если аргументов меньше трёх (где первый аргумент — имя программы, второй — первый символ, третий — второй символ), программа выводит сообщение "WHAAAAAT?" и завершается.
Поиск символов в алфавите:
Для двух переданных символов программа определяет их позиции в алфавите 'abcdefghijklmnopqrstuvwxyz{}*' с помощью функции get_idx.
Если хотя бы один символ не найден в алфавите (функция возвращает -1), выводится сообщение "Sorry, bro" и выполнение прекращается.
Шифрование строки:
Если оба символа присутствуют в алфавите, вызывается функция decode, которая шифрует строку, используя найденные индексы символов.

## bin14.exe

<img width="835" height="369" alt="Снимок экрана 2025-12-20 000217" src="https://github.com/user-attachments/assets/0692055d-02ce-4531-90be-d0cc742fc85c" />

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+8h] [ebp-254h]
  char v5; // [esp+Eh] [ebp-24Eh]
  char Str[25]; // [esp+Fh] [ebp-24Dh] BYREF
  char v7[4]; // [esp+28h] [ebp-234h] BYREF
  int v8[10]; // [esp+2Ch] [ebp-230h] BYREF
  int v9; // [esp+54h] [ebp-208h]
  _DWORD v10[128]; // [esp+58h] [ebp-204h] BYREF
  int i; // [esp+258h] [ebp-4h]

  v8[0] = 8;
  v8[1] = 7;
  v8[2] = 5;
  v8[3] = 4;
  v8[4] = 1;
  v8[5] = 3;
  v8[6] = 2;
  v8[7] = 6;
  v8[8] = 9;
  v8[9] = 10;
  qmemcpy(Str, "cPK}[aYr^@ZZR`C]TBP_\\Y_U", 24);
  Str[24] = 127;
  strcpy(v7, "UWE");
  if ( argc >= 2 )
  {
    v9 = strlen(argv[1]);
    for ( i = 0; i < v9; ++i )
    {
      v5 = argv[1][i];
      if ( v5 < 48 || v5 > 57 )
      {
        ((void (__cdecl *)(char *))((char *)&etext + 1))(aOnly09);
        return 2;
      }
      v10[i] = argv[1][i] - 48;
    }
    bubble_sort_sequence_executor_aka_transposition_performer(v8, v10, v9);
    v4 = 1;
    for ( i = 0; i < 10; ++i )
    {
      if ( v8[i] != i + 1 )
        v4 = 0;
    }
    if ( v4 )
    {
      for ( i = 0; i < strlen(Str); ++i )
        Str[i] ^= argv[1][i % v9];
      printf("Your flag: %s\n", Str);
    }
    else
    {
      ((void (__cdecl *)(char *))((char *)&etext + 1))(aHmmmNotExactly);
    }
    return 0;
  }
  else
  {
    ((void (__cdecl *)(char *))((char *)&etext + 1))(aGoAwayLazyStud);
    return 1;
  }
}
```

Вы должны запустить программу из командной строк, нужно запросить минимум два аргумента, которые состоят из цифр
Для успешного получения флага требуется предварительная сортировка списка v8 по возрастанию. Функция `bubble_sort` осуществляет эту сортировку, принимая на вход неотсортированный список v8, список v10 (содержащий отдельные символы введенного числа) и длину введенной строки v9.
Алгоритм сортировки основан на попарном обмене соседних элементов. То, какие именно элементы будут меняться местами, определяется значением из массива v10 по индексу i. Это значение указывает, на сколько байт нужно сместить текущий символ от начала списка v8, чтобы определить его новую позицию.

v8 = ‘87541326910‘.
Если мы хотим переместить цифру 1 в самое начало, мы сначала меняем местами 4 и 1. При i = 0, значение из v10 (допустим, оно равно 3) указывает, что символ должен сместиться на 12 байт от начала списка. Учитывая, что каждый символ в v8 занимает 4 байта, чтобы перейти от 8 к позиции 4 (где находится 1), нам нужно сделать 4 * 3 шага, где 3 – это значение из v10. В результате мы получим строку 87514326910.

Этот процесс повторяется для каждого символа, перемещая его на заданную позицию.
Для получения флага необходимо ввести строку `321054321543254354656`.

## bin15.exe

<img width="880" height="297" alt="Снимок экрана 2025-12-20 001113" src="https://github.com/user-attachments/assets/b403a923-a44a-4fc7-bab6-bece78990fe1" />


```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char Buffer[21]; // [esp+3h] [ebp-21h] BYREF
  int v5; // [esp+18h] [ebp-Ch]
  int v6; // [esp+1Ch] [ebp-8h]
  int v7; // [esp+20h] [ebp-4h]

  if ( argc >= 2 )
  {
    v7 = ((int (__cdecl *)(const char *))((char *)&etext + 1))(argv[1]);
    if ( v7 % 4 )
    {
      puts(aOkYouAreWrong);
      return 2;
    }
    else if ( !strcmp(argv[1], Str2) )
    {
      puts(aNotEnough);
      return 3;
    }
    else
    {
      v6 = hashf(argv[1]);
      v5 = hashf(aFlag123realfla_0);
      if ( v6 == v5 )
      {
        Buffer[0] = -29;
        Buffer[1] = -57;
        Buffer[2] = -19;
        Buffer[3] = -113;
        Buffer[4] = -34;
        Buffer[5] = -33;
        Buffer[6] = -28;
        Buffer[7] = -127;
        Buffer[8] = -10;
        Buffer[9] = -44;
        Buffer[10] = -27;
        Buffer[11] = -101;
        Buffer[12] = -6;
        Buffer[13] = -58;
        Buffer[14] = -11;
        Buffer[15] = -105;
        Buffer[16] = -18;
        Buffer[17] = -50;
        Buffer[18] = -11;
        Buffer[19] = -75;
        Buffer[20] = 0;
        decode(Buffer, v6);
        puts(Buffer);
      }
      return 0;
    }
  }
  else
  {
    puts(::Buffer);
    return 1;
  }
}
```

Для успешного прохождения всех проверок, требуется соблюдение следующих условий:
Командная строка должна содержать как минимум два аргумента.
Длина введенной строки должна быть кратна четырем.
Введенная строка не должна совпадать со строкой "FLAG{123REALFLAG!!!}".
Хеш введенной строки, вычисленный с помощью функции hashf, должен быть идентичен хешу предопределенной строки, также полученному с помощью hashf.
При выполнении всех вышеуказанных условий, будет произведена расшифровка содержимого списка Buffer. Каждый элемент списка будет подвергнут операции XOR с хешем, полученным с помощью hashf. Результат расшифровки будет выведен.
Для успешного прохождения всех проверок необходимо ввести строку, содержащую те же символы, что и FLAG{123FLAGREAL!!!}, но с перестановкой блоков по четыре символа. Примером такой строки является FLAG{123FLAG!!!}REAL.

флаг - FLAG{THIS_IS_MY_KEY}

