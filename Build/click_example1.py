import click

@click.command()
@click.argument('location')
@click.option('--api-key', '-a',
              help="Your goto for adding help")
def main(location):
    weather = current_weather(location)

    print("The weather in {location} right now is {weather}")

if __name__ == "__main__":
    main()
